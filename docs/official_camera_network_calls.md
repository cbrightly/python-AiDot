# Official Java implementation: network call map (API + device signaling)

## Scope and methodology
This document is derived directly from the decompiled Java sources under `sources/com/leedarson/smartcamera/kvswebrtc/**` and related signaling model classes. It focuses on **observed code paths only** and avoids assumptions where methods are partially decompiled or unavailable.

## 1) High-level architecture (observed)

```mermaid
sequenceDiagram
    participant App as Android App (kvswebrtc)
    participant API as HTTP API
    participant MQTT as MQTT Broker
    participant TCP as TCP Signaling Service
    participant Dev as Camera Device
    participant AWS as AWS KVS Signaling

    App->>API: GET /v15/api/webrtc/iceConfig?forceRefresh=0\n(headers: owner, token, terminal, appId, appVersion)
    API-->>App: ICE config JSON (cached to files/web/iceConfig/config.txt)

    App->>MQTT: publish iot/v1/s/{userId}/IPC/livePlayReq
    App->>TCP: nativeSendMessageToTarget(...livePlayReq...)
    Note over App,MQTT: Dual channel send wrapper races MQTT+TCP
    Note over App,TCP: First success wins, second success recorded as fallback ordering

    App->>MQTT: publish iot/v1/s/{userId}/IPC/webrtcReq (offer)
    App->>TCP: nativeSendMessageToTarget(...webrtcReq...)
    Dev-->>App: webrtcResp (answer path)

    App->>MQTT: publish iot/v1/s/{userId}/IPC/iceCandidateReq
    App->>TCP: nativeSendMessageToTarget(...iceCandidateReq...)
    Dev-->>App: candidate events

    App->>AWS: GetSignalingChannelEndpoint / GetIceServerConfig (KVS path)
    App->>AWS: WebSocket signaling (SDP_OFFER/SDP_ANSWER/ICE_CANDIDATE)
    Dev-->>App: Base64 messagePayload over WS
```

## 2) API calls (cloud HTTP)

### 2.1 ICE config HTTP endpoint
Observed in `IceConfigUpdateJobManager` (`m.java`):

- Base URL source: `SharePreferenceUtils.getPrefString(..., "httpServer", "")`
- Endpoint path: `"%s/v15/api/webrtc/iceConfig?forceRefresh=0"`
- HTTP manager call: `b0.b().K(...)`
- Header JSON fields set by code:
  - `owner: String`
  - `token: String` (from `accessToken`)
  - `terminal: String` (`"app"` literal)
  - `appId: String`
  - `appVersion: String`

Response is written to local file cache:
- directory: `${filesDir}/web/iceConfig`
- file: `${filesDir}/web/iceConfig/config.txt`

The cache validity check uses TTL thresholds for app-level and device-level records (local parse path). If valid, local cache is returned; otherwise network refresh is used.

## 3) Device signaling transport (MQTT + TCP dual channel)

## 3.1 Transport abstraction and behavior
`LdsSignalSwitchChanelWrap` (`channel/c.java`) wraps two channels:
- `TcpSignalSwitchChannel` (`channel/e.java`)
- `MqttSignalSwitchChannel` (`channel/d.java`)

Behavior:
- Each send operation creates a task id (`System.nanoTime()`)
- Message is sent on **both channels**
- First success marks task done and invokes caller callback
- If both channels fail, failure callback is triggered
- For OFFER messages, reporter stores answer source ordering:
  - `mqtt`, `tcp_mqtt`, `mqtt_tcp`, or `未收到` (not received)

### 3.2 MQTT channel send
`channel/d.java` calls:
- `LDSBaseMqttService.publish(configBean.topic, configBean, JSONObject(messageBody), handler)`

### 3.3 TCP channel send
`channel/e.java` calls:
- `TcpService.nativeSendMessageToTarget(deviceId, sendMsg, timeoutMs, typeCode, handler)`

TCP pre-send enriches JSON if missing:
- `srcAddr: "0.{userId}"`
- `seq: String` via `SpExtendHelper.generateNextSeq()`
- `tst: long` via `System.currentTimeMillis()`
- `tid: String` via `SpExtendHelper.generateTid()`

`typeCode` mapping observed:
- OFFER => `1`
- non-OFFER (CANDIDATE/LIVEPLAY) => `2`

## 4) MQTT topics and message types (observed)

The following outbound topics are explicit in code:

- `iot/v1/s/{userId}/IPC/livePlayReq`
- `iot/v1/s/{userId}/IPC/webrtcReq`
- `iot/v1/s/{userId}/IPC/iceCandidateReq`

The placeholder is replaced from app user id (`BaseApplication.b().d()` or shared pref `userId`).

## 5) Message schemas (observed fields/types)

## 5.1 `livePlayReq`
Model class: `LiveRequestParamsBean`

Top-level:
- `method: String = "livePlayReq"`
- `service: String = "IPC"`
- `srcAddr: String`
- `dstAddr: String`
- `livePlay: int` (default `1`)
- `payload: LivePlayPaylodBean`

Payload (`LivePlayPaylodBean`):
- `dseq: int`
- `dstAddr: String`
- `livePlay: int`
- `p2pCache: int`
- `peerid: String`
- `powerType: int`

Send assembly (`o.u(...)`) sets:
- top-level `srcAddr = "0.{userId}"`
- top-level `dstAddr = deviceId`
- payload `dstAddr = deviceId`
- payload `peerid = peerid`
- payload `dseq = dseq`
- payload `powerType/p2pCache` from `IpcService.getIPCDeviceInfoByDeviceId(...)`

## 5.2 `webrtcReq` (offer signaling to device)
Assembled in `o.q(...)` using nested JSON.

Envelope structure observed:
- outer JSON has `id = deviceId`
- `extends` object with:
  - `method = "webrtcReq"`
  - `devId = deviceId`
  - `service = "IPC"`
  - `userId = userId`
  - `payload = {...}`

`payload` fields observed:
- `dstAddr: String` (set to `deviceId`)
- `powerType: String` (from IPC device info; fallback `"1"`)
- `p2pCache: String` (from IPC device info; fallback `"0"`)
- `encOffer: int = 1`
- `liveMqtt: int = 1`
- `wPayload: JSONObject`
- `IceServerList: JSONArray`

`wPayload` fields observed:
- `peerid: String`
- `sts: long` (timestamp)
- `psk: String`
- `offer: { type: "offer", sdp: <compressed_sdp> }`

`IceServerList` behavior:
- KVS+LDS mode uses generated list including AWS stun URI and turn URIs
- otherwise uses pre-built local array from selected ICE config

## 5.3 `iceCandidateReq`
Assembled in `o.p(...)`:

Envelope:
- `id = deviceId`
- `extends.method = "iceCandidateReq"`
- `extends.devId = deviceId`
- `extends.service = "IPC"`
- `extends.userId = userId`
- `extends.payload = payloadObj`

Payload:
- `dstAddr = deviceId`
- `powerType` / `p2pCache` (same derivation/fallback style)
- `wPayload` object:
  - `peerid: String`
  - `sts: long`
  - `candidate: { candidate: String }`

## 5.4 `webrtcResp` (device answer)
Observed in two places:
- expected method string check inside `o.j(...)` (partially decompiled)
- synthetic error response construction in `o.a.b(...)` that creates `SdpAnswerBean` + `DataBean` with `method = "webrtcResp"`

Parsed structures used by app include:
- `DataBean.method: String`
- `DataBean.payload.offer.{type,sdp}`
- `DataBean.payload.peerid: String`
- `DataBean.code: int`
- `DataBean.desc: String`

## 6) KVS signaling path (AWS)

In addition to LDS MQTT/TCP signaling, the app also contains an AWS Kinesis Video signaling path (`f0.java`, `tyrus/n.java`):

- AWS clients used:
  - `AWSKinesisVideoClient` for signaling endpoints
  - `AWSKinesisVideoSignalingClient` for ICE server config
- Calls observed:
  - `getSignalingChannelEndpoint(...)`
  - `getIceServerConfig(...)`
- websocket signaling client (`tyrus/n.java`) receives/sends:
  - `SDP_OFFER`
  - `SDP_ANSWER`
  - `ICE_CANDIDATE`
- `Event.messagePayload` is Base64-encoded JSON and parsed into SDP/candidate objects.

## 7) Chinese log text translations (selected)

Key strings translated for operational meaning:

- `获取IceConfig数据：(开始)` -> “Fetching IceConfig data: (start)”
- `获取IceConfig数据（成功）` -> “Fetching IceConfig data (success)”
- `获取IceConfig数据(失败)` -> “Fetching IceConfig data (failure)”
- `媒体协商(数据准备ing)` -> “Media negotiation (preparing data)”
- `媒体协商（App==>设备）数据内容为` -> “Media negotiation (App => Device) payload is”
- `起播指令投递成功` -> “Start-play command delivered successfully”
- `候选人数据交换(App==>设备)` -> “ICE candidate exchange (App => Device)”
- `双通道发送失败` -> “Dual-channel send failed”
- `未收到` -> “Not received”

## 8) Direct implementation checklist for parity (strictly observed requirements)

To match what this Java implementation explicitly does, your client needs at minimum:

1. **ICE config acquisition + cache policy**
   - call `/v15/api/webrtc/iceConfig?forceRefresh=0`
   - use required headers (`owner`, `token`, `terminal`, `appId`, `appVersion`)
   - maintain local cache and TTL validation

2. **Dual-channel signaling send**
   - send each signaling command over MQTT and TCP concurrently
   - deduplicate first successful callback, track fallback ordering

3. **Topic and method names**
   - `livePlayReq`, `webrtcReq`, `iceCandidateReq`, and response parsing for `webrtcResp`
   - MQTT topics under `iot/v1/s/{userId}/IPC/...`

4. **Field-level message composition**
   - set `dstAddr = deviceId`
   - include `srcAddr = 0.{userId}` (at least where used in Java path)
   - include `peerid`, `dseq`, `powerType`, `p2pCache`, timestamps/sequence ids where applicable

5. **Offer/candidate payload formatting**
   - `webrtcReq` with `extends.payload.wPayload.offer` and optional `IceServerList`
   - `iceCandidateReq` with nested `wPayload.candidate.candidate`

6. **Response gating by peer id**
   - inbound answer/candidate handling checks expected peer id before applying

## 9) Unknown/partially decompiled areas (needs your clarification)

These are explicit gaps where code is truncated (`UnsupportedOperationException` in decompilation), so exact behavior cannot be guaranteed from this snapshot:

1. Full logic of `o.i(...)` (ICE config selection/merging details).
2. Full logic of `o.j(...)` (exact `webrtcResp` success/error branch handling and code mapping).
3. Full LDS inbound MQTT subscription registration path (topic subscriptions and dispatch source are not all visible in the inspected files).

If you want, I can do a second pass focused only on these three gaps and trace all call sites into `f0.java` and service interfaces to produce an exact “known vs unknown” matrix per function.

## 10) Field-by-field sample JSON corpus (observed schema examples)

> These are **schema-faithful examples** derived from the Java composition/parsing logic. Values are illustrative placeholders.

### 10.1 `livePlayReq` (App -> Camera via MQTT/TCP)

```json
{
  "method": "livePlayReq",
  "service": "IPC",
  "srcAddr": "0.123456789",
  "dstAddr": "A4D9XXXXDEVICE",
  "livePlay": 1,
  "payload": {
    "dseq": 1700012345,
    "dstAddr": "A4D9XXXXDEVICE",
    "livePlay": 1,
    "p2pCache": 0,
    "peerid": "peer_7f8a9b",
    "powerType": 1
  }
}
```

Field notes:
- `srcAddr`/`dstAddr`: `String`
- `livePlay`: `int`
- `payload.dseq`: `int`
- `payload.p2pCache`: `int`
- `payload.peerid`: `String`
- `payload.powerType`: `int`

### 10.2 `webrtcReq` (offer envelope, App -> Camera)

```json
{
  "id": "A4D9XXXXDEVICE",
  "extends": {
    "method": "webrtcReq",
    "devId": "A4D9XXXXDEVICE",
    "service": "IPC",
    "userId": "123456789",
    "payload": {
      "dstAddr": "A4D9XXXXDEVICE",
      "powerType": "1",
      "p2pCache": "0",
      "encOffer": 1,
      "liveMqtt": 1,
      "wPayload": {
        "peerid": "peer_7f8a9b",
        "sts": 1712345678901,
        "psk": "psk_or_token_here",
        "offer": {
          "type": "offer",
          "sdp": "<compressed_sdp_string>"
        }
      },
      "IceServerList": [
        {
          "Password": "turn_token",
          "Ttl": 86400,
          "Uris": [
            "stun:stun.kinesisvideo.us-east-1.amazonaws.com:443",
            "turn:example.turn.host:443?transport=udp"
          ],
          "Username": "turn_user"
        }
      ]
    }
  }
}
```

Field notes:
- `extends.method/devId/service/userId`: `String`
- `payload.powerType/p2pCache`: observed as `String` in this path
- `wPayload.sts`: `long`
- `offer.type/sdp`: `String`
- `IceServerList`: `JSONArray` of objects

### 10.3 `iceCandidateReq` (App -> Camera)

```json
{
  "id": "A4D9XXXXDEVICE",
  "extends": {
    "method": "iceCandidateReq",
    "devId": "A4D9XXXXDEVICE",
    "service": "IPC",
    "userId": "123456789",
    "payload": {
      "dstAddr": "A4D9XXXXDEVICE",
      "powerType": "1",
      "p2pCache": "0",
      "wPayload": {
        "peerid": "peer_7f8a9b",
        "sts": 1712345678912,
        "candidate": {
          "candidate": "candidate:0 1 UDP 2122252543 192.168.1.10 52182 typ host"
        }
      }
    }
  }
}
```

Field notes:
- `wPayload.candidate.candidate`: nested candidate string field
- topic-level behavior sets this request as publish-ack-only in MQTT config path

### 10.4 `webrtcResp` (Camera -> App expected parse shape)

```json
{
  "code": 200,
  "desc": "ok",
  "data": [
    {
      "code": 200,
      "method": "webrtcResp",
      "desc": "ok",
      "devId": "A4D9XXXXDEVICE",
      "service": "IPC",
      "srcAddr": "A4D9XXXXDEVICE",
      "seq": "1712345678",
      "payload": {
        "peerid": "peer_7f8a9b",
        "trackId": 0,
        "supportRtpExt": 1,
        "pskEnable": 0,
        "offer": {
          "type": "answer",
          "sdp": "v=0\\r\\n..."
        }
      }
    }
  ]
}
```

Field notes (from parse model usage):
- top-level `code`: `Integer`
- `data`: `List<DataBean>`
- `DataBean.method`: expected `"webrtcResp"`
- `DataBean.payload.offer.type`: expected `"answer"`
- `DataBean.payload.offer.sdp`: remote SDP

## 11) MQTT trace map for camera/IPC devices across streaming technologies

This section tracks MQTT behavior for camera devices only, regardless of stream transport.

### 11.1 LDS WebRTC / hybrid LDS+KVS path (explicit MQTT signaling)

Observed outbound MQTT topics:
- `iot/v1/s/{userId}/IPC/livePlayReq`
- `iot/v1/s/{userId}/IPC/webrtcReq`
- `iot/v1/s/{userId}/IPC/iceCandidateReq`

Observed send characteristics:
- messages are also sent over TCP in parallel (dual-channel)
- default publish ack behavior derives from topic name containing `Req`
- explicit override sets `iceCandidateReq` to ack-only behavior

Expected device response family (from parser/model usage):
- `webrtcResp` payloads are parsed as answer-bearing response objects
- `livePlayResp` is referenced in business logic changes and aligns with start-play gating flow

### 11.2 KVS-only stream signaling path

Observed signaling plane is WebSocket (`SDP_OFFER`/`SDP_ANSWER`/`ICE_CANDIDATE`) and AWS APIs.

MQTT conclusion for inspected KVS-only path:
- no distinct camera MQTT request topic set beyond LDS IPC topics was found in inspected KVS signaling classes.
- KVS control messages are carried by websocket payloads in this implementation segment.

### 11.3 TUTK/AVIOCTRL camera path

Observed camera control is AVIOCTRL-based (`IOTYPE_USER_IPCAM_*`) in `smartcamera/sdk/a.java` and related handlers.

MQTT conclusion for inspected TUTK path:
- no camera-control MQTT topic corpus analogous to `livePlayReq/webrtcReq/iceCandidateReq` was found in inspected TUTK control path; transport appears SDK/AV channel driven.

### 11.4 IPC event-style camera push handling (non-stream-setup telemetry/events)

Observed IPC event page identifiers in camera IPC processors:
- `IPC.event`
- `IPC.cloudEvents`
- also service routing pages like `IPC.live`, `IPC.securityCameras`, `IPC.radarMap`, `IPC.signalTest`

These indicate camera/IPC event routing surfaces, but exact MQTT topic strings carrying these event pages were not fully recoverable from the decompiled snippets inspected here.

## 12) Deep-dive on previously known decompilation gaps

This section revisits the prior gaps and records what is now recoverable from surrounding decompiled control flow.

### 12.1 Gap: `o.i(...)` ICE config selection/merge logic

**Now clarified from control-flow reconstruction:**

1. Input JSON is parsed into `IceConfigBean`.
2. `this.a` is reset to a new `JSONArray` and is used to store LDS-style `IceServerList` objects (`Password`, `Ttl`, `Uris`, `Username`).
3. Device-specific TURN selection:
   - iterate `IceConfigBean.dev`
   - match `dev.id == deviceId`
   - for matched device, append its URI list into one `IceServerList` item and push into `this.a`.
4. App-level STUN/TURN for peer connection list:
   - read first `app` element
   - choose `dnsUris` when present/non-empty, else fallback to `uris`
   - for each URI, build `PeerConnection.IceServer` using:
     - username = `app[0].id`
     - password = `app[0].token`
   - append into `peerIceServers` argument list.
5. Success path:
   - if callback listener exists and `peerIceServers.size() > 0`, call `listener.b()` and mark trace success.
6. Failure path:
   - when no servers found, emits `onException` with “current device not found suitable iceServer...” detail.

**What remains not fully visible:**
- Any branch pruning done by compiler/obfuscation around edge-case null handling and logging side effects.

### 12.2 Gap: `o.j(...)` `webrtcResp` handling and error mapping

**Now clarified from decompiled body:**

1. Parse response string into `SdpAnswerBean`.
2. Require top-level `code == 200`; otherwise trace/report as negotiation error.
3. Iterate `data[]` and process entries where `method == "webrtcResp"`.
4. For each `webrtcResp` item:
   - read `payload.peerid`, `payload.pskEnable`, `payload.trackId`, `payload.supportRtpExt`, `payload.offer`.
   - require `item.code == 200` and `payload.offer.type == "answer"`.
   - create `Event` object and push answer via callback `this.b.c(event)`.
5. Ack (`data[i].ack`) handling:
   - `ack.code == 200`: success trace.
   - `ack.code == -50002`: maps to “已达最大直播推流路数” class of max-stream error.
   - `ack.code == -50015`: maps to “sd卡最大连接数” class of SD-card/max-connection error.
   - non-success invokes prelink error callback `this.g.a(code, desc, step, peerId)`.
6. Timeout/error branch:
   - non-200 item code maps to timeout-style message and reporter failure.

**What remains not fully visible:**
- Full mapping table of all possible negative `ack.code` values beyond those explicitly present in decompiled branch checks.

### 12.3 Gap: inbound MQTT registration/dispatch for IPC camera callbacks

**Now clarified from `IpcServiceImpl` decompilation context:**

1. Device callback subscription topic template is explicit:
   - `iot/v1/cb/deviceId/#`
2. During full-update refresh, this template is expanded per camera device id and subscribed through `LDSBaseMqttService.subscribeTopic(...)` with a `{"topic": [ ... ]}` JSON body.
3. Removed devices are unsubscribed similarly by building the same template-per-device list and calling `unSubscribeTopic(...)`.
4. This callback channel is camera/IPC scoped (device-id keyed) and sits alongside outbound request topics (`iot/v1/s/{userId}/IPC/...`).

**What remains not fully visible:**
- Exact payload schemas delivered on `iot/v1/cb/{deviceId}/#` for every camera feature family, because subscription success callback is visible but message payload dispatch handlers are distributed/obfuscated.

## 13) Remaining unknowns after this gap pass

1. Complete callback message schema corpus for all `iot/v1/cb/{deviceId}/#` subtopics (especially non-live camera capabilities).
2. Full negative error-code taxonomy for `webrtcResp.ack.code` beyond `-50002` and `-50015` branches visible here.
3. Whether there are region/build-variant topic aliases not present in this decompiled build.
