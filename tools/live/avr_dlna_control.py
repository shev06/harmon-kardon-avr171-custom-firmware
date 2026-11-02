#!/usr/bin/env python3
"""
avr_dlna_control.py — Zero-firmware-risk DLNA/UPnP control client for the
Harman Kardon AVR 1710 (BridgeCo CE2DM870 media-bridge chip).

Every action here uses the receiver's own already-shipping, standards-based
UPnP AV stack (ports 80/8080). Nothing in this script touches firmware or
flash; it is plain network SOAP/HTTP, exactly like any DLNA controller app
(e.g. Windows "Cast to Device", BubbleUPnP) would use.

Discovered action surface (device: 192.168.0.65, confirmed live):

  RenderingControl (urn:schemas-upnp-org:service:RenderingControl:1)
    ListPresets(InstanceID) -> CurrentPresetNameList
    SelectPreset(InstanceID, PresetName='FactoryDefaults')
    GetMute(InstanceID, Channel='Master') -> CurrentMute
    SetMute(InstanceID, Channel='Master', DesiredMute)
    GetVolume(InstanceID, Channel='Master') -> CurrentVolume
    SetVolume(InstanceID, Channel='Master', DesiredVolume=0..100)

  ConnectionManager (urn:schemas-upnp-org:service:ConnectionManager:1)
    GetProtocolInfo() -> Source, Sink
    GetCurrentConnectionIDs() -> ConnectionIDs
    GetCurrentConnectionInfo(ConnectionID) -> Rcs/AVTransport IDs, ProtocolInfo, ...

  AVTransport (urn:schemas-upnp-org:service:AVTransport:1)
    SetAVTransportURI(InstanceID, CurrentURI, CurrentURIMetaData)
    SetNextAVTransportURI(InstanceID, NextURI, NextURIMetaData)
    GetMediaInfo(InstanceID) -> NrTracks, MediaDuration, CurrentURI, ...
    GetTransportInfo(InstanceID) -> CurrentTransportState/Status/Speed
    GetPositionInfo(InstanceID) -> Track, TrackDuration, RelTime, ...
    GetDeviceCapabilities(InstanceID) -> PlayMedia, RecMedia, RecQualityModes
    GetTransportSettings(InstanceID) -> PlayMode, RecQualityMode
    Stop(InstanceID) / Play(InstanceID, Speed='1') / Pause(InstanceID)
    Seek(InstanceID, Unit='TRACK_NR'|'REL_TIME', Target)
    Next(InstanceID) / Previous(InstanceID)
    SetPlayMode(InstanceID, NewPlayMode='NORMAL'|'SHUFFLE'|'REPEAT_ONE'|'REPEAT_ALL')
    GetCurrentTransportActions(InstanceID) -> Actions

  Confirmed accepted streaming formats (ConnectionManager::GetProtocolInfo Sink):
    audio/L16 PCM (44100/48000 Hz, mono/stereo), audio/mpeg (MP3),
    audio/x-ms-wma (base/full/wavetunes), audio/vnd.dlna.adts (AAC-ADTS)
  -> the receiver can be used as a DLNA "cast/play-to" target for these
     formats via SetAVTransportURI + Play, independent of the proprietary
     TCP:10025 XML dispatcher documented elsewhere in this project.

Usage:
  python3 avr_dlna_control.py get-volume
  python3 avr_dlna_control.py get-transport-info
  python3 avr_dlna_control.py set-volume 20          # MUTATES real device state
  python3 avr_dlna_control.py play-url http://.../track.mp3   # MUTATES real device state

Only the get-* / list-* / ListPresets commands are side-effect-free; every
other command changes real, audible receiver state (volume, mute, playback).
"""
import sys
import urllib.request

HOST = "192.168.0.65"
PORT = 8080


def soap_call(service: str, action: str, args: dict | None = None) -> str:
    args = args or {}
    body_args = "".join(f"<{k}>{v}</{k}>" for k, v in args.items())
    envelope = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        "<s:Body>"
        f'<u:{action} xmlns:u="urn:schemas-upnp-org:service:{service}:1">'
        f"{body_args}"
        f"</u:{action}>"
        "</s:Body></s:Envelope>"
    ).encode("utf-8")
    req = urllib.request.Request(
        f"http://{HOST}:{PORT}/{service}/ctrl",
        data=envelope,
        method="POST",
        headers={
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPACTION": f'"urn:schemas-upnp-org:service:{service}:1#{action}"',
        },
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        return resp.read().decode("utf-8", errors="replace")


COMMANDS = {
    "get-volume": ("RenderingControl", "GetVolume", {"InstanceID": 0, "Channel": "Master"}),
    "get-mute": ("RenderingControl", "GetMute", {"InstanceID": 0, "Channel": "Master"}),
    "list-presets": ("RenderingControl", "ListPresets", {"InstanceID": 0}),
    "get-transport-info": ("AVTransport", "GetTransportInfo", {"InstanceID": 0}),
    "get-media-info": ("AVTransport", "GetMediaInfo", {"InstanceID": 0}),
    "get-position-info": ("AVTransport", "GetPositionInfo", {"InstanceID": 0}),
    "get-device-caps": ("AVTransport", "GetDeviceCapabilities", {"InstanceID": 0}),
    "get-transport-actions": ("AVTransport", "GetCurrentTransportActions", {"InstanceID": 0}),
    "get-protocol-info": ("ConnectionManager", "GetProtocolInfo", {}),
    "get-connection-ids": ("ConnectionManager", "GetCurrentConnectionIDs", {}),
    # mutating:
    "stop": ("AVTransport", "Stop", {"InstanceID": 0}),
    "pause": ("AVTransport", "Pause", {"InstanceID": 0}),
    "next": ("AVTransport", "Next", {"InstanceID": 0}),
    "previous": ("AVTransport", "Previous", {"InstanceID": 0}),
}


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    cmd = sys.argv[1]

    if cmd in COMMANDS:
        service, action, args = COMMANDS[cmd]
        print(soap_call(service, action, args))
    elif cmd == "set-volume" and len(sys.argv) == 3:
        print(soap_call("RenderingControl", "SetVolume",
                         {"InstanceID": 0, "Channel": "Master", "DesiredVolume": int(sys.argv[2])}))
    elif cmd == "set-mute" and len(sys.argv) == 3:
        val = 1 if sys.argv[2].lower() in ("1", "true", "on") else 0
        print(soap_call("RenderingControl", "SetMute",
                         {"InstanceID": 0, "Channel": "Master", "DesiredMute": val}))
    elif cmd == "play-url" and len(sys.argv) == 3:
        uri = sys.argv[2]
        print(soap_call("AVTransport", "SetAVTransportURI",
                         {"InstanceID": 0, "CurrentURI": uri, "CurrentURIMetaData": ""}))
        print(soap_call("AVTransport", "Play", {"InstanceID": 0, "Speed": 1}))
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
