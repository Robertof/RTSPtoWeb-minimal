package main

import (
	"net/url"
	"strings"
	"time"

	"github.com/deepch/vdk/av"
	"github.com/deepch/vdk/format/rtspv2"
	"github.com/sirupsen/logrus"
)

//StreamServerRunStreamDo stream run do mux
func StreamServerRunStreamDo(streamID string, channelID string) {
	var status int
	defer func() {
		//TODO fix it no need unlock run if delete stream
		if status != 2 {
			Storage.StreamChannelUnlock(streamID, channelID)
		}
	}()
	for {
		baseLogger := log.WithFields(logrus.Fields{
			"module":  "core",
			"stream":  streamID,
			"channel": channelID,
			"func":    "StreamServerRunStreamDo",
		})

		baseLogger.WithFields(logrus.Fields{"call": "Run"}).Infoln("Run stream")
		opt, err := Storage.StreamChannelControl(streamID, channelID)
		if err != nil {
			baseLogger.WithFields(logrus.Fields{
				"call": "StreamChannelControl",
			}).Infoln("Exit", err)
			return
		}
		if opt.OnDemand && !Storage.ClientHas(streamID, channelID) {
			baseLogger.WithFields(logrus.Fields{
				"call": "ClientHas",
			}).Infoln("Stop stream no client")
			return
		}
		status, err = StreamServerRunStream(streamID, channelID, opt)
		if status > 0 {
			baseLogger.WithFields(logrus.Fields{
				"call": "StreamServerRunStream",
			}).Infoln("Stream exit by signal or not client")
			return
		}
		if err != nil {
			log.WithFields(logrus.Fields{
				"call": "Restart",
			}).Errorln("Stream error restart stream", err)
		}
		time.Sleep(2 * time.Second)

	}
}

//StreamServerRunStream core stream
func StreamServerRunStream(streamID string, channelID string, opt *ChannelST) (int, error) {
	if url, err := url.Parse(opt.URL); err == nil && strings.ToLower(url.Scheme) == "rtmp" {
		panic("rtmp support has been removed")
	}
	keyTest := time.NewTimer(20 * time.Second)
	checkClients := time.NewTimer(20 * time.Second)
	var preKeyTS = time.Duration(0)
	var Seq []*av.Packet
	RTSPClient, err := rtspv2.Dial(rtspv2.RTSPClientOptions{URL: opt.URL, InsecureSkipVerify: opt.InsecureSkipVerify, DisableAudio: !opt.Audio, DialTimeout: 3 * time.Second, ReadWriteTimeout: 5 * time.Second, Debug: opt.Debug, OutgoingProxy: true})
	if err != nil {
		return 0, err
	}
	Storage.StreamChannelStatus(streamID, channelID, ONLINE)
	defer func() {
		RTSPClient.Close()
		Storage.StreamChannelStatus(streamID, channelID, OFFLINE)
	}()
	var WaitCodec bool
	/*
		Example wait codec
	*/
	if RTSPClient.WaitCodec {
		WaitCodec = true
	} else {
		if len(RTSPClient.CodecData) > 0 {
			Storage.StreamChannelCodecsUpdate(streamID, channelID, RTSPClient.CodecData, RTSPClient.SDPRaw)
		}
	}
	log.WithFields(logrus.Fields{
		"module":  "core",
		"stream":  streamID,
		"channel": channelID,
		"func":    "StreamServerRunStream",
		"call":    "Start",
	}).Infoln("Success connection RTSP")
	for {
		select {
		//Check stream have clients
		case <-checkClients.C:
			if opt.OnDemand && !Storage.ClientHas(streamID, channelID) {
				return 1, ErrorStreamNoClients
			}
			checkClients.Reset(20 * time.Second)
		//Check stream send key
		case <-keyTest.C:
			return 0, ErrorStreamNoVideo
		//Read core signals
		case signals := <-opt.signals:
			switch signals {
			case SignalStreamStop:
				return 2, ErrorStreamStopCoreSignal
			case SignalStreamRestart:
				return 0, ErrorStreamRestart
			case SignalStreamClient:
				return 1, ErrorStreamNoClients
			}
		//Read rtsp signals
		case signals := <-RTSPClient.Signals:
			switch signals {
			case rtspv2.SignalCodecUpdate:
				Storage.StreamChannelCodecsUpdate(streamID, channelID, RTSPClient.CodecData, RTSPClient.SDPRaw)
				WaitCodec = false
			case rtspv2.SignalStreamRTPStop:
				return 0, ErrorStreamStopRTSPSignal
			}
		case packetRTP := <-RTSPClient.OutgoingProxyQueue:
			Storage.StreamChannelCastProxy(streamID, channelID, packetRTP)
		case packetAV := <-RTSPClient.OutgoingPacketQueue:
			if WaitCodec {
				continue
			}

			if packetAV.IsKeyFrame {
				keyTest.Reset(20 * time.Second)
				if preKeyTS > 0 {
					Seq = []*av.Packet{}
				}
				preKeyTS = packetAV.Time
			}
			Seq = append(Seq, packetAV)
			Storage.StreamChannelCast(streamID, channelID, packetAV)
		}
	}
}
