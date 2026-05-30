import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="python-aidot",
    version="0.4.0",
    author="aidotdev2024",
    url='https://github.com/cbrightly/python-AiDot',
    description="Control AIDOT WiFi lights and cameras",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=setuptools.find_packages(),
    install_requires=[
        "requests",
        "aiohttp",
        # Camera cloud APIs + MQTT signaling are part of the core camera support.
        "paho-mqtt>=2.0",
        "cryptography",
        "pycryptodome",
    ],
    extras_require={
        # Required for liveType=2 cameras (WebRTC-over-MQTT streaming, snapshots,
        # two-way audio).  Install with: pip install "python-aidot[webrtc] @ git+..."
        "webrtc": [
            "aiortc>=1.9.0",
            "av",
            "pylibsrtp",
            "pyopenssl",
            "numpy",
            "Pillow",
        ],
    },
    classifiers=(
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ),
)