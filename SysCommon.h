#pragma once

#pragma warning(push)
#pragma warning(disable:4996)

#include <iostream>
using namespace std;

#pragma warning(pop)

#include <vector>
#include <map>
#include <stdarg.h>

// define printf color
#define PRINT_COLOR

#if defined(WIN32) || defined(_WIN32) || defined(_WIN64)
#define PRINT_COLOR_BLUE	0x01
#define PRINT_COLOR_GREEN	0x02
#define PRINT_COLOR_AQUA	0x03
#define PRINT_COLOR_RED		0x04
#define PRINT_COLOR_PURPLE	0x05
#define PRINT_COLOR_YELLOW	0x06
#define PRINT_COLOR_BASIC	0x07
#else // defined(WIN32) || defined(_WIN32) || defined(_WIN64)
#define PRINT_COLOR_BASIC	"\033[0m"
#define PRINT_COLOR_RED		"\033[31m"
#define PRINT_COLOR_GREEN	"\033[32m"
#define PRINT_COLOR_YELLOW	"\033[33m"
#define PRINT_COLOR_BLUE	"\033[34m"
#define PRINT_COLOR_PURPLE	"\033[35m"
#define PRINT_COLOR_AQUA	"\033[36m"
#endif // defined(WIN32) || defined(_WIN32) || defined(_WIN64)

#if defined(WIN32) || defined(_WIN32) || defined(_WIN64)
static void SetPrintColor(const unsigned short &usColor = PRINT_COLOR_BASIC)
{
#if defined(PRINT_COLOR)
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, usColor);
#endif // defined(PRINT_COLOR)
}
#else // defined(WIN32) || defined(_WIN32) || defined(_WIN64)
static void SetPrintColor(const char *pColor = PRINT_COLOR_BASIC)
{
#if defined(PRINT_COLOR)
	printf(pColor);
#endif // defined(PRINT_COLOR)
}
#endif // defined(WIN32) || defined(_WIN32) || defined(_WIN64)
//

#if defined(WIN32) || defined(_WIN32) || defined(_WIN64)
static void PrintWithColor(const unsigned short &usColor, const char* fmt, ...)
{
#if defined(PRINT_COLOR)
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, usColor);

	va_list arglist;

	va_start(arglist, fmt);
	vprintf(fmt, arglist);
	va_end(arglist);

	SetConsoleTextAttribute(hConsole, PRINT_COLOR_BASIC);
#endif // defined(PRINT_COLOR)
}
#else // defined(WIN32) || defined(_WIN32) || defined(_WIN64)
static void PrintWithColor(const char *pColor, const char* fmt, ...)
{
#if defined(PRINT_COLOR)
	printf(pColor);

	va_list arglist;

	va_start(arglist, fmt);
	vprintf(fmt, arglist);
	va_end(arglist);
#endif // defined(PRINT_COLOR)
}
#endif // defined(WIN32) || defined(_WIN32) || defined(_WIN64)

#if defined(WIN32) || defined(_WIN32) || defined(_WIN64)
static void PrintWithColor(const char* msg, const unsigned short &usColor)
{
#if defined(PRINT_COLOR)
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, usColor);

	printf(msg);

	SetConsoleTextAttribute(hConsole, PRINT_COLOR_BASIC);
#endif // defined(PRINT_COLOR)
}
#else // defined(WIN32) || defined(_WIN32) || defined(_WIN64)
static void PrintWithColor(const char *pColor, const char* msg)
{
#if defined(PRINT_COLOR)
	printf(pColor);

	va_list arglist;

	va_start(arglist, fmt);
	vprintf(fmt, arglist);
	va_end(arglist);
#endif // defined(PRINT_COLOR)
}
#endif // defined(WIN32) || defined(_WIN32) || defined(_WIN64)

#ifndef SAFE_MEM_NEW
#define SAFE_MEM_NEW(Type, szMem)			(Type*)malloc(szMem * sizeof(Type))
#endif

#ifndef SAFE_MEM_DELETE
#define SAFE_MEM_DELETE(pMem)				if(pMem) { free(pMem); pMem = NULL; }
#endif

#ifndef SAFE_RELEASE
#define	SAFE_RELEASE(pObj)					if(pObj) { pObj->Release(); pObj = NULL; }
#endif

#ifndef	SAFE_DELETE
#define	SAFE_DELETE(pMem)					if(pMem) { delete pMem; pMem = NULL; }
#endif

#ifndef	SAFE_DELETE_ARRAY
#define	SAFE_DELETE_ARRAY(pMem)				if(pMem) { delete[] pMem; pMem = NULL; }
#endif

#ifndef SAFE_RESET
#define	SAFE_RESET(pMem)					if(pMem) { pMem.reset(); }
#endif

#ifndef	MAKE_BIT
#define	MAKE_BIT(x)							(0x01 << (x))
#endif

#ifndef	EXTRACT_BIT
#define	EXTRACT_BIT(nValue, nBitValue)		((nValue) & (nBitValue))
#endif

#ifndef	IS_BIT_SET
#define	IS_BIT_SET(nValue, nBitValue)		((bool)(EXTRACT_BIT(nValue, nBitValue) == (nBitValue)))
#endif

#ifndef	BIT_SET
#define	BIT_SET(nValue, nBitValue)			((nValue) |= nBitValue)
#endif

#ifndef	BIT_RESET
#define	BIT_RESET(nValue, nBitValue)		((nValue) &= ~(nBitValue))
#endif

#ifndef	MAKE_MASK
#define	MAKE_MASK(nBit)						(nBit ? 0xFFFFFFFF >> (32 - nBit) : NULL)
#endif

#ifndef	MAKE_MASK64
#define	MAKE_MASK64(nBit)					(nBit ? 0xFFFFFFFFFFFFFFFF >> (64 - nBit) : NULL)
#endif

//////////////////////////////////////////////////////////////////////////
#pragma pack(push, 1)

// VA
typedef struct _IVS_VA_LICENSE_AUTH_INFO
{
	std::string base_url;
	std::string activation_key;
	std::string license_info;
} IVS_VA_LICENSE_AUTH_INFO, *pIVS_VA_LICENSE_AUTH_INFO;

typedef struct _IVS_VA_EVENT_TYPE_INFO
{
	std::string event_name;
	unsigned int event_code;
	unsigned int alg_type;

	_IVS_VA_EVENT_TYPE_INFO()
	{
		event_code = 0;
		alg_type = 0;
	}

	unsigned operator == (const _IVS_VA_EVENT_TYPE_INFO *ptr) const
	{
		return (event_code == ptr->event_code);
	}
} IVS_VA_EVENT_TYPE_INFO, *pIVS_VA_EVENT_TYPE_INFO;

typedef struct _IVS_VA_LICENSE_INFO
{
	std::string license_key;
	unsigned int num_of_channel;
	std::vector<IVS_VA_EVENT_TYPE_INFO> vec_va_event_type_info;
	std::string expiration_date;

	_IVS_VA_LICENSE_INFO()
	{
		num_of_channel = 0;
	}
} IVS_VA_LICENSE_INFO, *pIVS_VA_LICENSE_INFO;

typedef struct _IVS_VA_ENGINE_DEVICE_REG_INFO
{
	std::string video_source_id;
	std::string title;

	unsigned operator == (const std::string &video_src_id) const
	{
		return (video_source_id == video_src_id);
	}
} IVS_VA_ENGINE_DEVICE_REG_INFO, *pIVS_VA_ENGINE_DEVICE_REG_INFO;

typedef std::vector<IVS_VA_ENGINE_DEVICE_REG_INFO> VecVAEngineDeviceRegInfo;

typedef struct _IVS_SERVER_DEVICE_REG_INFO
{
	bool use_receiver;
	bool use_data_compress;
	VecVAEngineDeviceRegInfo vec_va_engine_device_reg_info;

	_IVS_SERVER_DEVICE_REG_INFO()
	{
		use_receiver = false;
		use_data_compress = false;
	}

	void copy(const _IVS_SERVER_DEVICE_REG_INFO *ptr)
	{
		use_receiver = ptr->use_receiver;
		use_data_compress = ptr->use_data_compress;

		vec_va_engine_device_reg_info.clear();
		for (unsigned int i = 0; i < (unsigned int)ptr->vec_va_engine_device_reg_info.size(); i++)
		{
			vec_va_engine_device_reg_info.push_back(ptr->vec_va_engine_device_reg_info[i]);
		}
	}
} IVS_SERVER_DEVICE_REG_INFO, *pIVS_SERVER_DEVICE_REG_INFO;

typedef struct _IVS_VA_ENGINE_ASSIGN_INFO
{
	unsigned int va_engine_number;

	struct source_info
	{
		IVS_VA_ENGINE_DEVICE_REG_INFO va_engine_device_reg_info;

		enum class STATUS
		{
			NONE = -1,
			READY,
			RECEIVE,
			ANALYSIS
		};

		STATUS status;

		source_info()
		{
			status = STATUS::NONE;
		}
	};

	std::vector<source_info> vec_source_info;

	_IVS_VA_ENGINE_ASSIGN_INFO()
	{
		va_engine_number = 0;
	}

	void copy(const _IVS_VA_ENGINE_ASSIGN_INFO *ptr)
	{
		va_engine_number = ptr->va_engine_number;

		vec_source_info.clear();
		for (unsigned int i = 0; i < (unsigned int)ptr->vec_source_info.size(); i++)
		{
			vec_source_info.push_back(ptr->vec_source_info[i]);
		}
	}
} IVS_VA_ENGINE_ASSIGN_INFO, *pIVS_VA_ENGINE_ASSIGN_INFO;

typedef struct _IVS_VA_SERVER_INFO
{
	std::string ip;
	unsigned short port;
	std::vector<IVS_VA_LICENSE_INFO> vec_va_license_info;
	std::vector<IVS_VA_ENGINE_ASSIGN_INFO> vec_va_engine_assign_Info;

	_IVS_VA_SERVER_INFO()
	{
		port = 0;
	}
} IVS_VA_SERVER_INFO, *pIVS_VA_SERVER_INFO;

typedef struct _IVS_VA_SERVER_DB_INFO
{
	unsigned int id;
	std::string ip;
	unsigned short port;
	std::string va_license_info;
	std::string va_engine_assign_info;

	_IVS_VA_SERVER_DB_INFO()
	{
		id = 0;
		port = 0;
	}
} IVS_VA_SERVER_DB_INFO, *pIVS_VA_SERVER_DB_INFO;

typedef struct _IVS_VA_METADATA_SERVER_INFO
{
	std::string ip;
	unsigned short port;
	IVS_SERVER_DEVICE_REG_INFO server_device_reg_info;

	_IVS_VA_METADATA_SERVER_INFO()
	{
		port = 0;
	}
} IVS_VA_METADATA_SERVER_INFO, *pIVS_VA_METADATA_SERVER_INFO;

typedef struct _IVS_VA_METADATA_SERVER_DB_INFO
{
	unsigned int id;
	std::string ip;
	unsigned short port;
	std::string server_device_reg_info;

	_IVS_VA_METADATA_SERVER_DB_INFO()
	{
		id = 0;
		port = 0;
	}
} IVS_VA_METADATA_SERVER_DB_INFO, *pIVS_VA_METADATA_SERVER_DB_INFO;

typedef struct _IVS_VA_USER_INFO
{
	enum class AUTHORITY_TYPE
	{
		MANAGER = 0,
		OPERATOR,
		GENERAL_USER,
	};

	std::string user_name;
	std::string user_password;
	AUTHORITY_TYPE authority_type;
	unsigned int authority_level;

	enum AUTHORITY_TO_SETUP_UI_TYPE
	{
		SYSTEM_SETUP = 0,
		DEVICE_SETUP,
		VA_DETAIL_SETUP,
		EVENT_SETUP,
		STATUS,
		MAX_SETUP_UI_TYPE
	};

	unsigned int authority_to_setup_ui;
	unsigned int max_allocable_channel;

	_IVS_VA_USER_INFO()
	{
		authority_type = AUTHORITY_TYPE::OPERATOR;
		authority_level = 1;

		authority_to_setup_ui = 0;
		for (unsigned int i = AUTHORITY_TO_SETUP_UI_TYPE::DEVICE_SETUP; i < AUTHORITY_TO_SETUP_UI_TYPE::MAX_SETUP_UI_TYPE; i++)
		{
			unsigned int unMakeBit = MAKE_BIT(i);

			BIT_SET(authority_to_setup_ui, unMakeBit);
		}

		max_allocable_channel = 0;
	}

	unsigned operator == (const std::string &name) const
	{
		return (user_name == name);
	}

	void copy(const _IVS_VA_USER_INFO *ptr)
	{
		user_name = ptr->user_name;
		user_password = ptr->user_password;
		authority_type = ptr->authority_type;
		authority_level = ptr->authority_level;
		authority_to_setup_ui = ptr->authority_to_setup_ui;
		max_allocable_channel = ptr->max_allocable_channel;
	}
} IVS_VA_USER_INFO, *pIVS_VA_USER_INFO;

typedef std::map<std::string, IVS_VA_USER_INFO> MapVAUserInfo;

typedef struct _IVS_VA_USER_DB_INFO
{
	unsigned int id;
	std::string va_user_info;

	_IVS_VA_USER_DB_INFO()
	{
		id = 0;
	}
} IVS_VA_USER_DB_INFO, *pIVS_VA_USER_DB_INFO;

typedef struct _IVS_VA_DEVICE_INFO
{
	std::string manufacturer;
	std::string model_name;
	std::string server_ip;
	unsigned short server_port;
	std::string server_user_name;
	std::string server_user_password;
	std::string camera_ip;
	std::string camera_user_name;
	std::string camera_user_password;
	std::string title;
	std::string video_source_id;
	std::vector<std::string> vec_rtsp_object;

	struct playback_time_info
	{
		unsigned long long start_frame_time;
		unsigned long long end_frame_time;

		playback_time_info()
		{
			start_frame_time = 0;
			end_frame_time = 0;
		}

		void copy(const playback_time_info *ptr)
		{
			start_frame_time = ptr->start_frame_time;
			end_frame_time = ptr->end_frame_time;
		}
	};

	playback_time_info pb_time_info;

	unsigned int device_channel;
	unsigned int ptz;

	_IVS_VA_DEVICE_INFO()
	{
		server_port = 0;
		device_channel = 0;
		ptz = 0;
	}

	void copy(const _IVS_VA_DEVICE_INFO *ptr)
	{
		manufacturer = ptr->manufacturer;
		model_name = ptr->model_name;
		server_ip = ptr->server_ip;
		server_port = ptr->server_port;
		server_user_name = ptr->server_user_name;
		server_user_password = ptr->server_user_password;
		camera_ip = ptr->camera_ip;
		camera_user_name = ptr->camera_user_name;
		camera_user_password = ptr->camera_user_password;
		title = ptr->title;
		video_source_id = ptr->video_source_id;

		vec_rtsp_object.clear();
		for (unsigned int i = 0; i < (unsigned int)ptr->vec_rtsp_object.size(); i++)
		{
			vec_rtsp_object.push_back(ptr->vec_rtsp_object[i]);
		}

		pb_time_info.copy(&ptr->pb_time_info);

		device_channel = ptr->device_channel;
		ptz = ptr->ptz;
	}

	unsigned operator == (const _IVS_VA_DEVICE_INFO *ptr) const
	{
		return (video_source_id == ptr->video_source_id);
	}
} IVS_VA_DEVICE_INFO, *pIVS_VA_DEVICE_INFO;

typedef struct _IVS_VA_DEVICE_DB_INFO
{
	unsigned int va_server_info_id;
	std::string video_source_id;
	std::string va_device_info;

	_IVS_VA_DEVICE_DB_INFO()
	{
		va_server_info_id = 0;
	}

	unsigned operator == (const std::string &video_src_id) const
	{
		return (video_source_id == video_src_id);
	}
} IVS_VA_DEVICE_DB_INFO, *pIVS_VA_DEVICE_DB_INFO;

typedef struct _IVS_VA_ENGINE_SYSTEM_INFO
{
	unsigned int number_of_va_engine;
	unsigned int number_of_va_engine_channel;

	_IVS_VA_ENGINE_SYSTEM_INFO()
	{
		number_of_va_engine = 0;
		number_of_va_engine_channel = 0;
	}
} IVS_VA_ENGINE_SYSTEM_INFO, *pIVS_VA_ENGINE_SYSTEM_INFO;

typedef struct _IVS_VA_AREA
{
	unsigned int type;
	std::string id;
	std::vector<float> vec_point;

	_IVS_VA_AREA()
	{
		type = 0;
	}
} IVS_VA_AREA, *pIVS_VA_AREA;

typedef struct _IVS_VA_EVENT
{
	unsigned int ev_type;
	unsigned int alg_type;
	unsigned int sensitivity;

	_IVS_VA_EVENT()
	{
		ev_type = 0;
		alg_type = 0;
		sensitivity = 0;
	}

	unsigned operator == (const _IVS_VA_EVENT *ptr) const
	{
		return (ev_type == ptr->ev_type && alg_type == ptr->alg_type);
	}
} IVS_VA_EVENT, *pIVS_VA_EVENT;

typedef struct _IVS_VA_FILTER
{
	std::vector<unsigned int> vec_obj_type;
	std::vector<unsigned int> vec_obj_detail_type;
	std::vector<unsigned int> vec_color;
	unsigned int color_weight_value;		// 0 ~ 100
	std::vector<unsigned int> vec_speed;
	unsigned int direction;

	_IVS_VA_FILTER()
	{
		color_weight_value = 15;
		direction = 0;
	}
} IVS_VA_FILTER, *pIVS_VA_FILTER;

typedef struct _IVS_VA_RULE
{
	unsigned int roi_type;
	std::string roi_id;
	std::string roi_name;
	unsigned int roi_length;
	std::vector<float> vec_point;
	std::vector<IVS_VA_EVENT> vec_va_event;
	IVS_VA_FILTER va_filter;

	_IVS_VA_RULE()
	{
		roi_type = 0;
		roi_length = 0;
	}

	unsigned operator == (const _IVS_VA_EVENT *ptr) const
	{
		std::vector<IVS_VA_EVENT>::const_iterator iter = std::find(
			vec_va_event.begin(), vec_va_event.end(), ptr
		);

		return (iter != vec_va_event.end());
	}

	unsigned operator == (const std::string &id) const
	{
		return (roi_id == id);
	}
} IVS_VA_RULE, *pIVS_VA_RULE;

typedef struct _IVS_VA_ENGINE_RULE_SETUP_INFO
{
	unsigned int event_search_id;		// Use only smart search
	std::string video_source_id;
	unsigned int alg_onoff;				// on : 1, off : 0
	std::vector<float> vec_alg_fps;
	unsigned int org_width;
	unsigned int org_height;
	unsigned int alg_width;
	unsigned int alg_height;
	std::string sample_path;
	std::vector<IVS_VA_AREA> vec_va_area;
	std::vector<IVS_VA_RULE> vec_va_rule;

	_IVS_VA_ENGINE_RULE_SETUP_INFO()
	{
		event_search_id = 0;
		alg_onoff = 1;
		org_width = 0;
		org_height = 0;
		alg_width = 0;
		alg_height = 0;
	}

	void copy(const _IVS_VA_ENGINE_RULE_SETUP_INFO *ptr)
	{
		video_source_id = ptr->video_source_id;
		event_search_id = ptr->event_search_id;

		alg_onoff = ptr->alg_onoff;

		vec_alg_fps.clear();
		for (unsigned int i = 0; i < (unsigned int)ptr->vec_alg_fps.size(); i++)
		{
			vec_alg_fps.push_back(ptr->vec_alg_fps[i]);
		}

		org_width = ptr->org_width;
		org_height = ptr->org_height;
		alg_width = ptr->alg_width;
		alg_height = ptr->alg_height;
		sample_path = ptr->sample_path;

		vec_va_area.clear();
		for (unsigned int i = 0; i < ptr->vec_va_area.size(); i++)
		{
			vec_va_area.push_back(ptr->vec_va_area[i]);
		}

		vec_va_rule.clear();
		for (unsigned int i = 0; i < ptr->vec_va_rule.size(); i++)
		{
			vec_va_rule.push_back(ptr->vec_va_rule[i]);
		}
	}
} IVS_VA_ENGINE_RULE_SETUP_INFO, *pIVS_VA_ENGINE_RULE_SETUP_INFO;

typedef struct _IVS_VA_ENGINE_RULE_SETUP_DB_INFO
{
	unsigned int va_server_info_id;
	std::string video_source_id;
	std::string va_engine_rule_setup_info;

	_IVS_VA_ENGINE_RULE_SETUP_DB_INFO()
	{
		va_server_info_id = 0;
	}
} IVS_VA_ENGINE_RULE_SETUP_DB_INFO, *pIVS_VA_ENGINE_RULE_SETUP_DB_INFO;

typedef struct _IVS_VA_ENGINE_CALIBRATION_INFO
{

	_IVS_VA_ENGINE_CALIBRATION_INFO()
	{

	}

	void copy(const _IVS_VA_ENGINE_CALIBRATION_INFO *ptr)
	{

	}
} IVS_VA_ENGINE_CALIBRATION_INFO, *pIVS_VA_ENGINE_CALIBRATION_INFO;

typedef struct _IVS_VA_ENGINE_CALIBRATION_DB_INFO
{
	unsigned int va_server_info_id;
	std::string video_source_id;
	std::string va_engine_calibration_info;

	_IVS_VA_ENGINE_CALIBRATION_DB_INFO()
	{
		va_server_info_id = 0;
	}
} IVS_VA_ENGINE_CALIBRATION_DB_INFO, *pIVS_VA_ENGINE_CALIBRATION_DB_INFO;

#define IVS_SCHEDULE
#if defined(IVS_SCHEDULE)
typedef struct _IVS_VA_ENGINE_DAY_OF_WEEK_SCHEDULE
{
	enum { DAY_OF_WEEK_COUNT = 7 };
	enum { MAX_TIME_INDEX = 48 };

	unsigned int day_of_week;
	std::map<unsigned int, std::vector<IVS_VA_EVENT_TYPE_INFO>> map_hourly_schedule;

	_IVS_VA_ENGINE_DAY_OF_WEEK_SCHEDULE()
	{
		day_of_week = 0;
	}

	unsigned operator == (const unsigned int &dayofweek) const
	{
		return (day_of_week == dayofweek);
	}
} IVS_VA_ENGINE_DAY_OF_WEEK_SCHEDULE, *pIVS_VA_ENGINE_DAY_OF_WEEK_SCHEDULE;
#else // defined(IVS_SCHEDULE)
typedef struct _IVS_VA_ENGINE_DAY_OF_WEEK_SCHEDULE
{
	unsigned int day_of_week;

	struct TIME_TABLE
	{
		std::string start_time;
		std::string end_time;
	};

	std::vector<TIME_TABLE> vec_time_table;

	_IVS_VA_ENGINE_DAY_OF_WEEK_SCHEDULE()
	{
		day_of_week = 0;
	}
} IVS_VA_ENGINE_DAY_OF_WEEK_SCHEDULE, *pIVS_VA_ENGINE_DAY_OF_WEEK_SCHEDULE;
#endif // defined(IVS_SCHEDULE)

typedef struct _IVS_VA_ENGINE_SCHEDULE_INFO
{
	std::string id;
	std::string name;
	std::vector<IVS_VA_ENGINE_DAY_OF_WEEK_SCHEDULE> vec_va_engine_day_of_week_schedule;

	void copy(const _IVS_VA_ENGINE_SCHEDULE_INFO *ptr)
	{
		id = ptr->id;
		name = ptr->name;

		vec_va_engine_day_of_week_schedule.clear();
		for (unsigned int i = 0; i < (unsigned int)ptr->vec_va_engine_day_of_week_schedule.size(); i++)
		{
			vec_va_engine_day_of_week_schedule.push_back(ptr->vec_va_engine_day_of_week_schedule[i]);
		}
	}
} IVS_VA_ENGINE_SCHEDULE_INFO, *pIVS_VA_ENGINE_SCHEDULE_INFO;

typedef struct _IVS_VA_ENGINE_SCHEDULE_DB_INFO
{
	unsigned int va_server_info_id;
	std::string video_source_id;
	std::string va_engine_schedule_info;

	_IVS_VA_ENGINE_SCHEDULE_DB_INFO()
	{
		va_server_info_id = 0;
	}
} IVS_VA_ENGINE_SCHEDULE_DB_INFO, *pIVS_VA_ENGINE_SCHEDULE_DB_INFO;

typedef struct _IVS_SETUP_UPDATED_INFO
{
	std::string user_name;
	std::string date_time;

	void copy(const _IVS_SETUP_UPDATED_INFO *ptr)
	{
		user_name = ptr->user_name;
		date_time = ptr->date_time;
	}
} IVS_SETUP_UPDATED_INFO, *pIVS_SETUP_UPDATED_INFO;

typedef struct _IVS_VA_SETUP_INFO
{
	IVS_VA_DEVICE_INFO va_device_info;
	IVS_VA_ENGINE_RULE_SETUP_INFO va_engine_rule_setup_info;
	IVS_VA_ENGINE_CALIBRATION_INFO va_engine_calibration_info;
	IVS_VA_ENGINE_SCHEDULE_INFO va_engine_schedule_info;
	unsigned int status;
	IVS_SETUP_UPDATED_INFO updated_info;

	_IVS_VA_SETUP_INFO()
	{
		status = 0;
	}

	void copy(const _IVS_VA_SETUP_INFO *ptr)
	{
		va_device_info.copy(&ptr->va_device_info);
		va_engine_rule_setup_info.copy(&ptr->va_engine_rule_setup_info);
		va_engine_calibration_info.copy(&ptr->va_engine_calibration_info);
		va_engine_schedule_info.copy(&ptr->va_engine_schedule_info);
		status = ptr->status;
		updated_info.copy(&ptr->updated_info);
	}
} IVS_VA_SETUP_INFO, *pIVS_VA_SETUP_INFO;

typedef struct _IVS_VA_SETUP_DB_INFO
{
	unsigned int id;
	IVS_VA_DEVICE_DB_INFO va_device_db_info;
	std::string va_engine_rule_setup_info;
	std::string va_engine_calibration_info;
	std::string va_engine_schedule_info;
	unsigned int status;
	std::string updated_info;

	_IVS_VA_SETUP_DB_INFO()
	{
		id = 0;
		status = 0;
	}

	unsigned operator == (const _IVS_VA_SETUP_DB_INFO *ptr) const
	{
		return ((id == ptr->id)
			&& (va_device_db_info.video_source_id == ptr->va_device_db_info.video_source_id));
	}

	unsigned operator == (const std::string &video_src_id) const
	{
		return (va_device_db_info.video_source_id == video_src_id);
	}
} IVS_VA_SETUP_DB_INFO, *pIVS_VA_SETUP_DB_INFO;

typedef struct _IVS_VA_ENGINE_SESSION_STATUS_INFO
{
	std::string video_source_id;

	// Use only smart search
	unsigned int event_search_id;
	//

	unsigned int live_video_frame_count;
	unsigned int live_video_fps;
	float live_video_bitrate;

	union
	{
		struct
		{
			unsigned int basic_process_frame_count;
			unsigned int basic_process_fps;

			unsigned int light_process_frame_count;
			unsigned int light_process_fps;

			unsigned int deep_learning_process_frame_count;
			unsigned int deep_learning_process_fps;
		} va_fps;
	};

	// Use only in smart search.
	float analysis_progress_percentage;
	//

	std::vector<IVS_VA_EVENT_TYPE_INFO> vec_va_event_type_info;

	_IVS_VA_ENGINE_SESSION_STATUS_INFO()
	{
		event_search_id = 0;

		Initialize();
	}

	void Initialize()
	{
		live_video_frame_count = 0;
		live_video_fps = 0;
		live_video_bitrate = 0.f;

		va_fps.basic_process_frame_count = 0;
		va_fps.basic_process_fps = 0;

		va_fps.deep_learning_process_frame_count = 0;
		va_fps.deep_learning_process_fps = 0;

		// Use only in smart search
		analysis_progress_percentage = 0.f;
		//
	}

	void SetVideoSourceID(const std::string &strVideoSrcID) { video_source_id = strVideoSrcID; }

	// Use only in smart search
	void SetEventSearchID(const unsigned int &unEventSearchID) { event_search_id = unEventSearchID; }
	//

	void IncreaseLiveVideoFrameCount() { live_video_frame_count++; }
	void IncreaseBasicFrameCount() { va_fps.basic_process_frame_count++; }
	void IncreaseLightFrameCount() { va_fps.light_process_frame_count++; }
	void IncreaseDeepLearningFrameCount() { va_fps.deep_learning_process_frame_count++; }

	// Use only in smart search
	void SetAnalysisProgressPercentage(const float fPercentage) { analysis_progress_percentage = fPercentage; }
	//

	unsigned operator == (const std::string &video_src_id) const
	{
		return (video_source_id == video_src_id);
	}
} IVS_VA_ENGINE_SESSION_STATUS_INFO, *pIVS_VA_ENGINE_SESSION_STATUS_INFO;

typedef struct _IVS_VA_ENGINE_STATUS_INFO
{
	unsigned int va_engine_number;
	double va_engine_cpu_usage;
	double va_engine_memory_usage;
	std::vector<IVS_VA_ENGINE_SESSION_STATUS_INFO> vec_va_engine_session_status_info;

	_IVS_VA_ENGINE_STATUS_INFO()
	{
		va_engine_number = 0;
		va_engine_cpu_usage = 0.f;
		va_engine_memory_usage = 0.f;
	}
} IVS_VA_ENGINE_STATUS_INFO, *pIVS_VA_ENGINE_STATUS_INFO;

typedef struct _IVS_SERVER_STATUS_INFO
{
	std::string server_ip;
	unsigned int server_type;
	double server_cpu_usage;
	double server_memory_usage;
	double total_cpu_usage;
	double total_memory_usage;
	std::vector<IVS_VA_ENGINE_STATUS_INFO> vec_va_engine_status_info;

	_IVS_SERVER_STATUS_INFO()
	{
		server_type = 0;
		server_cpu_usage = 0.f;
		server_memory_usage = 0.f;
		total_cpu_usage = 0.f;
		total_memory_usage = 0.f;
	}
} IVS_SERVER_STATUS_INFO, *pIVS_SERVER_STATUS_INFO;

typedef struct _IVS_VA_OBJECT_RECT
{
	float x;
	float y;
	float width;
	float height;

	_IVS_VA_OBJECT_RECT()
	{
		x = 0.f;
		y = 0.f;
		width = 0.f;
		height = 0.f;
	}
} IVS_VA_OBJECT_RECT, *pIVS_VA_OBJECT_RECT;

typedef struct _IVS_VA_OBJECT_TRACE
{
	float x;
	float y;

	_IVS_VA_OBJECT_TRACE()
	{
		x = 0.f;
		y = 0.f;
	}
} IVS_VA_OBJECT_TRACE, *pIVS_VA_OBJECT_TRACE;

typedef struct _IVS_VA_OBJECT_EVENT_INFO
{
	int event_type;
	std::string event_roi_id;
	int start_ev;
	long long ev_start_time;
	long long ev_end_time;

	_IVS_VA_OBJECT_EVENT_INFO()
	{
		event_type = 0;
		start_ev = 0;
		ev_start_time = 0;
		ev_end_time = 0;
	}

	unsigned operator == (const unsigned int &ev) const
	{
		return (start_ev == ev);
	}
} IVS_VA_OBJECT_EVENT_INFO, *pIVS_VA_OBJECT_EVENT_INFO;

typedef struct _IVS_VA_OBJECT_INFO
{
	int id;
	int object_type;
	int object_detail_type;
	std::vector<int> vec_colors;
	int speed;
	unsigned int direction;
	unsigned long long appearance_time;
	IVS_VA_OBJECT_RECT va_object_rect;
	std::vector<IVS_VA_OBJECT_TRACE> vec_va_object_trace;
	std::vector<IVS_VA_OBJECT_EVENT_INFO> vec_va_object_event_info;

	_IVS_VA_OBJECT_INFO()
	{
		id = 0;
		object_type = 0;
		object_detail_type = 0;
		speed = 0;
		direction = 0;
		appearance_time = 0;
	}
} IVS_VA_OBJECT_INFO, *pIVS_VA_OBJECT_INFO;

typedef struct _IVS_VA_LINE_COUNT_INFO
{
	unsigned long long count_in;
	unsigned long long count_out;

	_IVS_VA_LINE_COUNT_INFO()
	{
		count_in = 0;
		count_out = 0;
	}
} IVS_VA_LINE_COUNT_INFO, *pIVS_VA_LINE_COUNT_INFO;

typedef struct _IVS_VA_LANES_INFO
{
	std::string roi_id;
	int density;
	int speed;

	struct object_type
	{
		int car;
		int bus;
		int truck;

		object_type()
		{
			car = 0;
			bus = 0;
			truck = 0;
		}
	};

	object_type total_volume;
	object_type stopped;
	object_type upward;
	object_type right;
	object_type left;
	object_type uturn;

	int waiting_time;

	_IVS_VA_LANES_INFO()
	{
		density = 0;
		speed = 0;

		waiting_time = 0;
	}
} IVS_VA_LANES_INFO, *pIVS_VA_LANES_INFO;

typedef struct _IVS_VA_OBJECT_RESULT_INFO
{
	std::string video_source_id;
	unsigned int event_search_id;		// Use only smart search
	unsigned long long frame_time;
	unsigned int frame_millisec;
	std::vector<IVS_VA_OBJECT_INFO> vec_va_object_info;
	std::vector<IVS_VA_LINE_COUNT_INFO> vec_va_line_count_info;
	std::vector<IVS_VA_LANES_INFO> vec_va_lanes_info;

	// [2021-03-29] tyjoo : Number of total object
	int number_of_total_human;
	int number_of_total_vehicle;
	//

	_IVS_VA_OBJECT_RESULT_INFO()
	{
		event_search_id = 0;
		frame_time = 0;
		frame_millisec = 0;

		number_of_total_human = 0;
		number_of_total_vehicle = 0;
	}
} IVS_VA_OBJECT_RESULT_INFO, *pIVS_VA_OBJECT_RESULT_INFO;

typedef struct _IVS_VA_EVENT_THUMBNAIL_IMAGE_INFO
{
	int width;
	int height;
	std::string data;

	_IVS_VA_EVENT_THUMBNAIL_IMAGE_INFO()
	{
		width = 0;
		height = 0;
	}
} IVS_VA_EVENT_THUMBNAIL_IMAGE_INFO, *pIVS_VA_EVENT_THUMBNAIL_IMAGE_INFO;

typedef struct _IVS_VA_EVENT_THUMBNAIL_FILE_INFO
{
	std::string path;
	std::string name;
	unsigned long long offset;

	_IVS_VA_EVENT_THUMBNAIL_FILE_INFO()
	{
		offset = 0;
	}
} IVS_VA_EVENT_THUMBNAIL_FILE_INFO, *pIVS_VA_EVENT_THUMBNAIL_FILE_INFO;

typedef struct _IVS_VA_EVENT_THUMBNAIL_INFO
{
	IVS_VA_EVENT_THUMBNAIL_FILE_INFO va_event_thumbnail_file_info;
} IVS_VA_EVENT_THUMBNAIL_INFO, *pIVS_VA_EVENT_THUMBNAIL_INFO;

//////////////////////////////////////////////////////////////////////////
// Auto Tracking
typedef struct _IVS_AUTO_TRACKING_SETUP_INFO
{
	std::string video_source_id;
	std::string manufacturer;
	int home_preset;
	bool activation;

	_IVS_AUTO_TRACKING_SETUP_INFO()
	{
		home_preset = 0;
		activation = false;
	}

	void copy(const _IVS_AUTO_TRACKING_SETUP_INFO *ptr)
	{
		video_source_id = ptr->video_source_id;
		manufacturer = ptr->manufacturer;
		home_preset = ptr->home_preset;
		activation = ptr->activation;
	}
} IVS_AUTO_TRACKING_SETUP_INFO, *pIVS_AUTO_TRACKING_SETUP_INFO;

typedef struct _IVS_AUTO_TRACKING_OBJECT_INFO
{
	int id;
	int image_width;
	int image_height;
	std::vector<float> vec_object_rect;

	_IVS_AUTO_TRACKING_OBJECT_INFO()
	{
		id = -1;
		image_width = 0;
		image_height = 0;
	}
} IVS_AUTO_TRACKING_OBJECT_INFO, *pIVS_AUTO_TRACKING_OBJECT_INFO;
//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
// Face Recognition
typedef struct _IVS_VA_FACE_RECOG_INFO
{
	std::wstring person_id;
	bool new_id;
	std::wstring name;
	std::wstring gender;
	float age;
	float sentiment;
	bool smile;
	std::vector<std::wstring> vec_tag;
	bool ignore;
	std::wstring merged_with;
	std::wstring media_id;
	float offset_x;
	float offset_y;
	float relative_width;
	float relative_height;
	unsigned long long root_person_add_date;
	unsigned long long exp_date;
	unsigned int occurrence;
	unsigned long long last_occurrence_date;
	std::wstring external_id;
	std::wstring person_type;

	// In attributes
	float predict_age;
	std::wstring predict_gender;
	float confidence;
	float center_pose_quality;
	float sharpness_quality;
	float contrast_quality;

	/*IVS_VA_FACE_ATTRIBUTE_INFO va_face_attribute_info;*/
	/*std::vector<IVS_VA_FACE_SIMILAR> vec_va_face_similar;*/

	_IVS_VA_FACE_RECOG_INFO()
	{
		new_id = false;
		age = -1;
		sentiment = 0;
		smile = false;
		ignore = false;
		offset_x = -1;
		offset_y = -1;
		relative_width = -1;
		relative_height = -1;
		occurrence = 0;
		root_person_add_date = exp_date = last_occurrence_date = 0;
	}
} IVS_VA_FACE_RECOG_INFO, *pIVS_VA_FACE_RECOG_INFO;

typedef struct _IVS_VA_FACE_RECOG_RESULT_INFO
{
	bool account_updated;
	unsigned long long detection_time;
	std::vector<IVS_VA_FACE_RECOG_INFO> vec_va_face_recog_info;
	unsigned char* image_buffer;
	int image_size;

	_IVS_VA_FACE_RECOG_RESULT_INFO()
	{
		account_updated = false;
		detection_time = 0;
		image_buffer = NULL;
		image_size = 0;
	}
} IVS_VA_FACE_RECOG_RESULT_INFO, *pIVS_VA_FACE_RECOG_RESULT_INFO;
//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
// Event
typedef struct _IVS_EVENT_SERVER_INFO
{
	std::string ip;
	unsigned short port;
	IVS_SERVER_DEVICE_REG_INFO server_device_reg_info;
} IVS_EVENT_SERVER_INFO, *pIVS_EVENT_SERVER_INFO;

typedef struct _IVS_EVENT_SERVER_DB_INFO
{
	unsigned int id;
	std::string ip;
	unsigned short port;
	std::string server_device_reg_info;
} IVS_EVENT_SERVER_DB_INFO, *pIVS_EVENT_SERVER_DB_INFO;

typedef struct _IVS_EVENT_VENDOR_INFO
{
	enum class VENDOR_TYPE
	{
		NONE = 0,
		MILESTONE,
		INNODEP,
		NXWITNESS,
		REALHUB,
		TELCOWARE,
		INCON,
		DIVISYS,
		OPTEX,
		LGCNS,
		DANUSYS,
		MAX
	};

	std::string name;
	VENDOR_TYPE type;
	std::string ip;
	unsigned short port;
	std::string user_name;
	std::string user_password;
	std::string description;

	_IVS_EVENT_VENDOR_INFO()
	{
		type = VENDOR_TYPE::NONE;
		port = 0;
	}

	void copy(const _IVS_EVENT_VENDOR_INFO *ptr)
	{
		name = ptr->name;
		type = ptr->type;
		ip = ptr->ip;
		port = ptr->port;
		user_name = ptr->user_name;
		user_password = ptr->user_password;
		description = ptr->description;
	}
} IVS_EVENT_VENDOR_INFO, *pIVS_EVENT_VENDOR_INFO;

typedef struct _IVS_EVENT_SERVICE_INFO
{
	std::string event_name;
	unsigned int event_code;

	struct source_info
	{
		std::string video_source_id;
		std::string camera_ip;
		std::string title;

		unsigned operator == (const std::string &video_src_id) const
		{
			return (video_source_id == video_src_id);
		}
	};

	std::vector<source_info> vec_source_info;

	_IVS_EVENT_SERVICE_INFO()
	{
		event_code = 0;
	}

	unsigned operator == (const unsigned int &ev_code) const
	{
		return (event_code == ev_code);
	}
} IVS_EVENT_SERVICE_INFO, *pIVS_EVENT_SERVICE_INFO;

typedef struct _IVS_EVENT_ALARM_SETUP_INFO
{
	std::vector<IVS_EVENT_VENDOR_INFO> vec_event_vendor_info;
	std::vector<IVS_EVENT_SERVICE_INFO> vec_event_service_info;
} IVS_EVENT_ALARM_SETUP_INFO, *pIVS_EVENT_ALARM_SETUP_INFO;

typedef struct _IVS_EVENT_SETUP_INFO
{
	IVS_EVENT_ALARM_SETUP_INFO event_alarm_setup_info;
	IVS_SETUP_UPDATED_INFO updated_info;
} IVS_EVENT_SETUP_INFO, *pIVS_EVENT_SETUP_INFO;

typedef struct _IVS_EVENT_SETUP_DB_INFO
{
	unsigned int id;
	unsigned int event_server_info_id;
	std::string event_alarm_setup_info;
	std::string updated_info;

	_IVS_EVENT_SETUP_DB_INFO()
	{
		id = 0;
		event_server_info_id = 0;
	}
} IVS_EVENT_SETUP_DB_INFO, *pIVS_EVENT_SETUP_DB_INFO;

//////////////////////////////////////////////////////////////////////////
// Stream
typedef struct _IVS_STREAM_SERVER_ASSIGN_INFO
{
	std::string stream_server_addr;
	unsigned short stream_server_port;

	struct DEVICE_INFO
	{
		std::string video_source_id;
		std::string title;
	};

	std::vector<DEVICE_INFO> vec_device_info;
} IVS_STREAM_SERVER_ASSIGN_INFO, *pIVS_STREAM_SERVER_ASSIGN_INFO;

typedef struct _IVS_STREAM_SERVER_MNG_INFO
{
	std::string ip;
	unsigned short port;
	unsigned int main_manager;
	IVS_STREAM_SERVER_ASSIGN_INFO stream_server_assign_info;

	_IVS_STREAM_SERVER_MNG_INFO()
	{
		port = 0;
		main_manager = 0;
	}
} IVS_STREAM_SERVER_MNG_INFO, *pIVS_STREAM_SERVER_MNG_INFO;

typedef struct _IVS_STREAM_SERVER_MNG_DB_INFO
{
	unsigned int id;
	std::string ip;
	unsigned short port;
	unsigned int main_manager;
	std::string stream_server_assign_info;

	_IVS_STREAM_SERVER_MNG_DB_INFO()
	{
		id = 0;
		port = 0;
		main_manager = 0;
	}
} IVS_STREAM_SERVER_MNG_DB_INFO, *pIVS_STREAM_SERVER_MNG_DB_INFO;

typedef struct _IVS_STREAM_SERVER_INFO
{
	std::string ip;
	unsigned short port;
	unsigned short rtsp_port;
	unsigned int number_of_max_channel;

	_IVS_STREAM_SERVER_INFO()
	{
		port = 0;
		rtsp_port = 0;
		number_of_max_channel = 0;
	}
} IVS_STREAM_SERVER_INFO, *pIVS_STREAM_SERVER_INFO;

typedef struct _IVS_STREAM_SERVER_DB_INFO
{
	unsigned int id;
	std::string ip;
	unsigned short port;
	unsigned short rtsp_port;
	unsigned int number_of_max_channel;

	_IVS_STREAM_SERVER_DB_INFO()
	{
		id = 0;
		port = 0;
		rtsp_port = 0;
		number_of_max_channel = 0;
	}
} IVS_STREAM_SERVER_DB_INFO, *pIVS_STREAM_SERVER_DB_INFO;

typedef struct _IVS_THIRD_PARTY_SERVER_INFO
{
	unsigned int manufacturer_type;
	std::string ip;
	unsigned short port;
	std::string user_name;
	std::string user_password;

	_IVS_THIRD_PARTY_SERVER_INFO()
	{
		manufacturer_type = 0;
		port = 0;
	}

	bool operator==(const _IVS_THIRD_PARTY_SERVER_INFO & target) const
	{
		return
			(manufacturer_type == target.manufacturer_type) &&
			(ip == target.ip) &&
			(port == target.port) &&
			(user_name == target.user_name) &&
			(user_password == target.user_password);
	}

	bool operator!=(const _IVS_THIRD_PARTY_SERVER_INFO & target) const
	{
		return
			(manufacturer_type != target.manufacturer_type) ||
			(ip != target.ip) ||
			(port != target.port) ||
			(user_name != target.user_name) ||
			(user_password != target.user_password);
	}

	void copy(const _IVS_THIRD_PARTY_SERVER_INFO *ptr)
	{
		manufacturer_type = ptr->manufacturer_type;
		ip = ptr->ip;
		port = ptr->port;
		user_name = ptr->user_name;
		user_password = ptr->user_password;
	}
} IVS_THIRD_PARTY_SERVER_INFO, *pIVS_THIRD_PARTY_SERVER_INFO;

typedef struct _IVS_THIRD_PARTY_SERVER_DB_INFO
{
	unsigned int id;
	unsigned int manufacturer_type;
	std::string ip;
	unsigned short port;
	std::string user_name;
	std::string user_password;

	_IVS_THIRD_PARTY_SERVER_DB_INFO()
	{
		id = 0;
		manufacturer_type = 0;
		port = 0;
	}
} IVS_THIRD_PARTY_SERVER_DB_INFO, *pIVS_THIRD_PARTY_SERVER_DB_INFO;


// new by(경민)
typedef struct _IVS_STREAM_DEVICE_INFO
{
	std::string video_source_id;
	std::string camera_ip;
	unsigned short port;
	std::string camera_user_name;
	std::string camera_user_password;
	std::string title;
	std::string model_name;
	std::string main_stream;
	std::string sub_stream;
	// 1 for main stream, otherwise for secondary stream
	unsigned int device_channel;
	unsigned short stream_rtsp_port;
	
	void *property_info;
	
	_IVS_STREAM_DEVICE_INFO()
	{
		device_channel = 0;
		stream_rtsp_port = 0;
		property_info = NULL;
	}

	bool operator==(const _IVS_STREAM_DEVICE_INFO & target) const
	{
	/*	bool isEqual = (video_source_id == target.video_source_id) &&
			(camera_ip == target.camera_ip) &&
			(port == target.port) &&
			(camera_user_name == target.camera_user_name) &&
			(camera_user_password == target.camera_user_password) &&
			(title == target.title) &&
			(model_name == target.model_name) &&
			(main_stream == target.main_stream) &&
			(sub_stream == target.sub_stream) &&
			(device_channel == target.device_channel) &&
			(stream_rtsp_port == target.stream_rtsp_port);*/

		return video_source_id == target.video_source_id;

		//if (!isEqual) return false;
		//return true;
	}

	void copy(const _IVS_STREAM_DEVICE_INFO *ptr)
	{
		video_source_id = ptr->video_source_id;
		camera_ip = ptr->camera_ip;
		port = ptr->port;
		camera_user_name = ptr->camera_user_name;
		camera_user_password = ptr->camera_user_password;
		title = ptr->title;
		model_name = ptr->model_name;
		main_stream = ptr->main_stream;
		sub_stream = ptr->sub_stream;
		device_channel = ptr->device_channel;
		//[21_02_16]yhkim Add stream_stream_rtsp
		stream_rtsp_port = ptr->stream_rtsp_port;	//assign = Server Port, Non Assign = 0
		property_info = ptr->property_info;
	}
}IVS_STREAM_DEVICE_INFO, *pIVS_STREAM_DEVICE_INFO;

typedef struct _IVS_STREAM_DEVICE_DB_INFO
{
	unsigned int id;
	unsigned int stream_server_info_id;
	unsigned int third_party_server_info_id;
	std::string video_source_id;
	std::string device_info;

	_IVS_STREAM_DEVICE_DB_INFO()
	{
		id = 0;
		stream_server_info_id = 0;
		third_party_server_info_id = 0;
	}
} IVS_STREAM_DEVICE_DB_INFO, *pIVS_STREAM_DEVICE_DB_INFO;

typedef struct _IVS_STREAM_DEVICE_ASSIGN_INFO
{
	IVS_THIRD_PARTY_SERVER_INFO third_party_server_info;
	std::vector<IVS_STREAM_DEVICE_INFO> vec_stream_device_info;

	//[21_03_10]yhkim DeviceList vector Memory Off
	//~_IVS_STREAM_DEVICE_ASSIGN_INFO()
	//{
	//	std::vector<IVS_STREAM_DEVICE_INFO>().swap(vec_stream_device_info);
	//}

	void copy(const _IVS_STREAM_DEVICE_ASSIGN_INFO *ptr)
	{
		third_party_server_info.copy(&ptr->third_party_server_info);

		vec_stream_device_info.clear();

		for (unsigned int i = 0; i < (unsigned int)ptr->vec_stream_device_info.size(); i++)
		{
			vec_stream_device_info.push_back(ptr->vec_stream_device_info[i]);
		}
	}
} IVS_STREAM_DEVICE_ASSIGN_INFO, *pIVS_STREAM_DEVICE_ASSIGN_INFO;

typedef struct _IVS_STREAM_RTSP_DEVICE_DB_INFO 
{
	unsigned int idx;
	std::string strVideoSrcID;
	std::string strDeviceInfo;

	_IVS_STREAM_RTSP_DEVICE_DB_INFO() 
	{
		idx = 0;
		strVideoSrcID = "";
		strDeviceInfo = "";
	}

	void copy(const _IVS_STREAM_RTSP_DEVICE_DB_INFO *ptr)
	{
		strVideoSrcID = ptr->strVideoSrcID;
		strDeviceInfo = ptr->strDeviceInfo;
	}
}IVS_STREAM_RTSP_DEVICE_DB_INFO, *pIVS_STREAM_RTSP_DEVICE_DB_INFO;

//[21/03/11] yhkim Stream Setting Client Full, Assign Device Info Struct
typedef struct _IVS_STREAM_SETTINGCLIENT_DEVICE_INFO
{
	bool bIsStreaming;
	IVS_STREAM_DEVICE_INFO stream_device_Info;
	_IVS_STREAM_SETTINGCLIENT_DEVICE_INFO()
	{
		bIsStreaming = false;
	}

	void copy(const _IVS_STREAM_SETTINGCLIENT_DEVICE_INFO *ptr)
	{
		bIsStreaming = ptr->bIsStreaming;
		stream_device_Info = ptr->stream_device_Info;
	}
} IVS_STREAM_SETTINGCLIENT_DEVICE_INFO, *pIVS_STREAM_SETTINGCLIENT_DEVICE_INFO;

typedef struct _IVS_STREAM_SETTINGCLIENT_DEVICE_INFO_LIST
{
	IVS_THIRD_PARTY_SERVER_INFO third_party_server_info;
	std::vector<IVS_STREAM_SETTINGCLIENT_DEVICE_INFO> vec_stream_settingClient_device_info;

	// Device Info List vector Memory Off
	~_IVS_STREAM_SETTINGCLIENT_DEVICE_INFO_LIST()
	{
		std::vector<IVS_STREAM_SETTINGCLIENT_DEVICE_INFO>().swap(vec_stream_settingClient_device_info);
	}

	void copy(const _IVS_STREAM_SETTINGCLIENT_DEVICE_INFO_LIST *ptr)
	{
		third_party_server_info.copy(&ptr->third_party_server_info);

		vec_stream_settingClient_device_info.clear();

		for (unsigned int i = 0; i < (unsigned int)ptr->vec_stream_settingClient_device_info.size(); i++)
		{
			vec_stream_settingClient_device_info.push_back(ptr->vec_stream_settingClient_device_info[i]);
		}
	}
	void copyOld(const _IVS_STREAM_DEVICE_ASSIGN_INFO *ptr)
	{
		third_party_server_info.copy(&ptr->third_party_server_info);
		
		vec_stream_settingClient_device_info.clear();
		IVS_STREAM_SETTINGCLIENT_DEVICE_INFO tempStreamSettingClientDeviceInfo;
		for (unsigned int i = 0; i < (unsigned int)ptr->vec_stream_device_info.size(); i++)
		{
			tempStreamSettingClientDeviceInfo.bIsStreaming = false;
			tempStreamSettingClientDeviceInfo.stream_device_Info.copy(&ptr->vec_stream_device_info.at(i));
			vec_stream_settingClient_device_info.push_back(tempStreamSettingClientDeviceInfo);
		}
	}
	
} IVS_STREAM_SETTINGCLIENT_DEVICE_INFO_LIST, pIVS_STREAM_SETTINGCLIENT_DEVICE_INFO_LIST;

typedef struct _IVS_STREAM_SETTINGCLIENT_ASSIGN_LIST
{
	unsigned int nRTSPPort;
	IVS_THIRD_PARTY_SERVER_INFO third_party_server_info;
	IVS_STREAM_DEVICE_INFO streamDeviceInfo;

	void copy(const _IVS_STREAM_SETTINGCLIENT_ASSIGN_LIST *ptr)
	{
		nRTSPPort = ptr->nRTSPPort;
		third_party_server_info.copy(&ptr->third_party_server_info);
		streamDeviceInfo.copy(&ptr->streamDeviceInfo);
	}

}IVS_STREAM_SETTINGCLIENT_ASSIGN_LIST, *pIVS_STREAM_SETTINGCLIENT_ASSIGN_LIST;

//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
// Smart Search
typedef struct _IVS_EVENT_SEARCH_DB_INFO
{
	unsigned int id;
	unsigned int event_search_id;
	std::string event_search_history_info;

	_IVS_EVENT_SEARCH_DB_INFO()
	{
		id = 0;
		event_search_id = 0;
	}
} IVS_EVENT_SEARCH_DB_INFO, *pIVS_EVENT_SEARCH_DB_INFO;

typedef struct _IVS_EVENT_SEARCH_HISTORY_INFO
{
	unsigned int camera_id;
	std::string camera_name;
	std::string user_name;
	std::string video_source_id;
	unsigned long long start_search_time;
	unsigned long long end_search_time;
	unsigned long long start_analysis_time;
	unsigned long long end_analysis_time;
	unsigned int status;						// 0 : Server error, 1 : VA complete, 2 : VA cancel
	std::string message;

	_IVS_EVENT_SEARCH_HISTORY_INFO()
	{
		camera_id = 0;
		start_search_time = 0;
		end_search_time = 0;
		start_analysis_time = 0;
		end_analysis_time = 0;
		status = 0;
	}
} IVS_EVENT_SEARCH_HISTORY_INFO, *pIVS_EVENT_SEARCH_HISTORY_INFO;

typedef struct _IVS_EVENT_SEARCH_INFO
{
	unsigned int event_search_id;
	IVS_EVENT_SEARCH_HISTORY_INFO event_search_history_info;

	_IVS_EVENT_SEARCH_INFO()
	{
		event_search_id = 0;
	}
} IVS_EVENT_SEARCH_INFO, *pIVS_EVENT_SEARCH_INFO;
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////////////////////////////////
// 
typedef struct _IVS_VA_METADATA_INFO
{
	std::vector<IVS_VA_ENGINE_RULE_SETUP_INFO> vec_va_engine_rule_setup_info;
	std::vector<IVS_VA_OBJECT_RESULT_INFO> vec_va_object_result_info;
	IVS_VA_EVENT_THUMBNAIL_INFO va_event_thumbnail_info;
} IVS_VA_METADATA_INFO, *pIVS_VA_METADATA_INFO;

typedef struct _IVS_VA_METADATA_DB_INFO
{
	unsigned int id;
	unsigned int event_server_info_id;
	std::string va_engine_rule_setup_info;
	std::string va_object_result_info;
	std::string va_event_thumbnail_info;

	_IVS_VA_METADATA_DB_INFO()
	{
		id = 0;
		event_server_info_id = 0;
	}
} IVS_VA_METADATA_DB_INFO, *pIVS_VA_METADATA_DB_INFO;

#pragma pack(pop)
//////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////
typedef struct _IVS_STREAM_DEVICE_TEST_INPUT_INFO
{
	std::string strVideoSrcID;
	unsigned int manufacturerType;
	std::string strAddr;
	unsigned short usPort;
	std::string strUserName;
	std::string strUserPwd;
	//std::vector<std::string> vecRTSPObj;		[21/01/08 kmchoi] DeviceInfo 구조체 변경TEST위한 주석
	std::string main_stream;
	std::string sub_stream;
	////
	unsigned int unDevChannel;

	void copy(const _IVS_STREAM_DEVICE_TEST_INPUT_INFO *ptr)
	{
		manufacturerType = ptr->manufacturerType;
		strAddr = ptr->strAddr;
		usPort = ptr->usPort;
		strUserName = ptr->strUserName;
		strUserPwd = ptr->strUserPwd;

		/*vecRTSPObj.clear();
		for (unsigned int i = 0; i < (unsigned int)ptr->vecRTSPObj.size(); i++)
		{
		vecRTSPObj.push_back(ptr->vecRTSPObj[i]);
		}*/
		main_stream = ptr->main_stream;
		sub_stream = ptr->sub_stream;

		unDevChannel = ptr->unDevChannel;
	}
} IVS_STREAM_DEVICE_TEST_INPUT_INFO, *pIVS_STREAM_DEVICE_TEST_INPUT_INFO;
//////////////////////////////////////////////////////////////////////////

enum class IVS_PRODUCT_TYPE
{
	BASIC,
	SMART_SEARCH,
	SMART_MONITORING
};

static std::string GetProductTypeName(const IVS_PRODUCT_TYPE &productType)
{
	std::string strProductType;

	switch (productType)
	{
		case IVS_PRODUCT_TYPE::BASIC:					strProductType = "Basic";					break;
		case IVS_PRODUCT_TYPE::SMART_SEARCH:			strProductType = "Smart Search";			break;
		case IVS_PRODUCT_TYPE::SMART_MONITORING:		strProductType = "Smart Monitoring";		break;
	}

	return strProductType;
}

#if defined(WIN32) || defined(_WIN32) || defined(_WIN64)
// Define user window message
#define	WM_USER_SHELL_ICON WM_USER

#define	WM_USER_TERMINATE_SIGNAL WM_USER + 100
#define WM_USER_SERVER_START_NOTIFY WM_USER + 101
//
#endif // defined(WIN32) || defined(_WIN32) || defined(_WIN64)

#define IVS_PROCESS_AFFINITY_INFO "Setup\\IVS_PROCESS_AFFINITY_INFO"
#define IVS_SYSTEM_INFO "Setup\\IVS_SYSTEM_INFO"
#define IVS_EVENT_INFO "Setup\\IVS_EVENT_INFO"
#define IVS_VA_DEEPLEARNING_PROCESS_INFO "Setup\\IVS_VA_DEEPLEARNING_PROCESS_INFO"
#define IVS_ISD_SYSTEM_INFO "Setup\\IVS_ISD_SYSTEM_INFO"

enum { IVS_STREAM_SERVER_MNG_PORT = 7000 };
enum { IVS_STREAM_SERVER_PORT = 7001 };
enum { IVS_STREAM_SERVER_RTSP_PORT = 8554 };
enum { IVS_VA_SERVER_PORT = 10000 };
enum { IVS_EVENT_SERVER_PORT = 10001 };
enum { IVS_VA_METADATA_SERVER_PORT = 10100 };
enum { IVS_VA_METADATA_SUBSCRIBER_ADDITIONAL_PORT = 100 };
enum { IVS_AUTO_TRACKING_SERVER_PORT = 11000 };
enum { IVS_ISD_SERVER_PORT = 12000 };

enum { IVS_VA_ENGINE_RTSP_SERVER_DEFAULT_PORT = 9554 };
enum { IVS_VA_METADATA_RTSP_SERVER_DEFAULT_PORT = 10554 };

enum
{
	STATUS_VA_ENGINE_SETUP_NONE = 0,
	STATUS_VA_ENGINE_SETUP_ADD,
	STATUS_VA_ENGINE_SETUP_DELETE,
	STATUS_VA_ENGINE_SETUP_ADDED_DELETE
};

enum class IVS_VA_ALG_TYPE
{
	NONE = -1,
	BASIC,
	LIGHT,
	DEEP_LEARNING,
	FACE_RECOGNITION,
	MOTION_VECTOR
};

enum class IVS_VA_EVENT_CODE
{
	INTRUSION = 1,
	LOITERING = 2,
	LINE_CROSSING = 3,
	FIRE = 4,
	SMOKE = 5,

	VIOLENCE = 51,
	FALLDOWN = 52,
	RUNNING = 53,
	CROWD = 54,
	ABNORMAL = 55,
	ABNORMAL_CALLING = 56,
	ABNORMAL_TAKINGPHOTO = 57,
	KNEEINGDOWN = 57,

	ITS_TRACKING = 60,
	ITS_UPWARD = 61,
	ITS_LTURN = 62,
	ITS_RTURN = 63,
	ITS_UTURN = 64,
	ITS_DENSITY = 65,
	ITS_SPEED = 66,

	POSE1 = 101,
	POSE2 = 102,

	ABANDONMENT = 151,
	THEFT = 152,

	PEDESTRIAN = 201,
	VEHICLE_STOPPING = 202,
	WRONG_WAY = 203,
	OBJECT_FALLING = 204,

	HUMAN_COUNTING = 251,
	VEHICLE_COUNTING = 252,

	SOS = 301,
	NO_HELMET = 302,
	NO_HARNESS = 303,
	JUMPING = 304,
	BREAKCAM = 305,
	HUGGING = 306,
	HITTING_WALL = 307,
	CALLING = 308,
	RAILWAY_SLEEPING = 310,
	RAILWAY_ABANDON = 311,

	HEATMAP = 351,
	WAITING_LINE = 352,
	WATER_LEVEL = 353,
	NO_SEAT_BELT = 354,
	TAIGATING = 355,
	ILLEGAL_PARKING = 356,

	ILLEGAL_SITE = 357,
	BOAT = 358,
	APPEARANCE_CARRIER = 359,
	APPEARANCE_OBJECT = 360,
	SUBMERSION = 361,

	// Extended code
	FACE = 401,
	MOTION = 402,

	VEHICLE_STATE_TRACKING = 1800
};

enum class IVS_VA_OBJECT_TYPE
{
	NONE = -1,
	HUMAN,
	VEHICLE,
	HEAD,
	BOAT,
	OBJECT,
	AIR_PLANE,
	ANIMAL
};

enum class IVS_VA_OBJECT_HUMAN_DETAIL_TYPE
{
	NONE = 0,

	// Gender
	MALE = 1001,
	FEMEALE,

	// Age
	ADULT = 2001,
	CHILD,

	// Clothes
	T_SHIRT = 3001,
	SWEATER,
	PULL_OVER = SWEATER,
	PANTS,
	TROUSERS = PANTS,
	DRESS,
	COAT,
	SHIRT,
	SANDAL,
	SNEAKERS,
	BOOTS,

	// Belongings
	BAG = 4001,
	PHONE,
	HELMET,
	CAP,
	UMBRELLA,

	// Hair
	LONG_HAIR = 5001,
	SHORT_HAIR,

	// Vehicle
	BICYCLE = 6001,
	WHEELCHAIR,
	BABY_STROLLER
};

enum class IVS_VA_OBJECT_VEHICLE_DETAIL_TYPE
{
	NONE = 0,

	// 4 Wheel
	SEDAN = 1001,
	VAN,
	BUS,
	TRUCK,
	SUV,
	TAXI,

	// 2 Wheel
	MOTORCYCLE = 2001,

	// Special
	FIRE_TRUCK = 3001,
	PATROL_CAR,
	AMBULANCE,
	CONTAINER_CAR,
	CONSTRUCTION_CAR,

	// State
	STATE_STOP,
	STATE_MOVING,
	STATE_STOP_WHILE_MOVING,
};

enum class IVS_VA_OBJECT_HEAD_DETAIL_TYPE
{
	NONE = 0


};

enum class IVS_VA_OBJECT_BOAT_DETAIL_TYPE
{
	NONE = 0


};

enum class IVS_VA_OBJECT_OBJECT_DETAIL_TYPE
{
	NONE = 0


};

enum class IVS_VA_OBJECT_AIRPLANE_DETAIL_TYPE
{
	NONE = 0


};

enum class IVS_VA_OBJECT_ANIMAL_DETAIL_TYPE
{
	NONE = 0


};
