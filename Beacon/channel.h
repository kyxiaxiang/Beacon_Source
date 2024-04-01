#pragma once

void ChannelListen(char* buffer, int length);
void ChannelLSocketTcpPivot(char* buffer, int length);
void ChannelLSocketClose(char* buffer, int length);
void ChannelLSocketBind(char* buffer, int length, int ipAddress);
void ChannelConnect(char* buffer, int length);
void ChannelClose(char* buffer, int length);
void ChannelSend(char* buffer, int length);