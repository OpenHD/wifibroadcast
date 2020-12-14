#!/bin/bash
# Given a PC with 2 wifi cards connected that support monitor mode,
# This starts the tx on one of them and the rx on the other one

#MY_TX="wlp3s0"
#MY_TX="wlxc4e984126183"
MY_TX="wlx000f00460445" # ALFA card
#MY_TX="wlx6cfdb9b2a156" #PW-DN421
#MY_TX="wlx0018e7bd24db"

MY_RX="wlxc4e9840e3cbe"
#MY_RX_SECONDARY="wlxc4e984126183"
WFB_FOLDER="/home/consti10/Desktop/wifibroadcast"

FEC_K=0
FEC_N=0

sudo rfkill unblock wifi
#sudo killall ifplugd #stop management of interface

sudo ifconfig $MY_TX down
sudo iw dev $MY_TX set monitor otherbss fcsfail
sudo ifconfig $MY_TX up
sudo iwconfig $MY_TX channel 10
#sudo iw dev $MY_TX set channel "6" HT40+

sudo ifconfig $MY_RX down
sudo iw dev $MY_RX set monitor otherbss fcsfail
sudo ifconfig $MY_RX up
sudo iwconfig $MY_RX channel 10
#sudo iwconfig $MY_RX channel "6" HT40+

## test with multiple RXes
#sudo ifconfig $MY_RX_SECONDARY down
#sudo iw dev $MY_RX_SECONDARY set monitor otherbss fcsfail
#sudo ifconfig $MY_RX_SECONDARY up
#sudo iwconfig $MY_RX_SECONDARY channel 6


# $WFB_FOLDER/wfb_tx -k $FEC_K -n $FEC_N -u 6000 -p 60 -M 7 -K $WFB_FOLDER/drone.key $MY_TX
xterm -hold -e $WFB_FOLDER/wfb_tx -k $FEC_K -n $FEC_N -u 6000 -p 60 -M 4 -B 40 -K $WFB_FOLDER/drone.key $MY_TX &

$WFB_FOLDER/wfb_rx -k $FEC_K -n $FEC_N -c 127.0.0.1 -u 6100 -p 60 -K $WFB_FOLDER/gs.key $MY_RX

#other usefull commands:
#sudo iw dev
#nc -u localhost 6000
#nc -u -l localhost 6100
