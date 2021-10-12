/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 Dmitry Kozlyuk
 */

/* Tracing GUID: C5C835BB-5CFB-4757-B1D4-9DD74662E212 */
#define WPP_CONTROL_GUIDS \
	WPP_DEFINE_CONTROL_GUID( \
		VIRT2PHYS_TRACE_GUID, \
		(C5C835BB, 5CFB, 4757, B1D4, 9DD74662E212), \
		WPP_DEFINE_BIT(TRACE_GENERAL))

#define WPP_FLAG_LEVEL_LOGGER(flag, level) \
	WPP_LEVEL_LOGGER(flag)

#define WPP_FLAG_LEVEL_ENABLED(flag, level) \
	(WPP_LEVEL_ENABLED(flag) && \
		WPP_CONTROL(WPP_BIT_ ## flag).Level >= level)

#define WPP_LEVEL_FLAGS_LOGGER(lvl, flags) \
	WPP_LEVEL_LOGGER(flags)

#define WPP_LEVEL_FLAGS_ENABLED(lvl, flags) \
	(WPP_LEVEL_ENABLED(flags) && \
		WPP_CONTROL(WPP_BIT_ ## flags).Level >= lvl)

/*
 * WPP orders static parameters before dynamic parameters.
 * To support trace functions defined below which sets FLAGS and LEVEL,
 * a custom macro must be defined to reorder the arguments
 * to what the .tpl configuration file expects.
 */
#define WPP_RECORDER_FLAGS_LEVEL_ARGS(flags, lvl) \
	WPP_RECORDER_LEVEL_FLAGS_ARGS(lvl, flags)
#define WPP_RECORDER_FLAGS_LEVEL_FILTER(flags, lvl) \
	WPP_RECORDER_LEVEL_FLAGS_FILTER(lvl, flags)

/*
begin_wpp config

USEPREFIX(TraceError, "[%!FUNC!] ");
FUNC TraceError{FLAGS=TRACE_GENERAL, LEVEL=TRACE_LEVEL_ERROR}(MSG, ...);

USEPREFIX(TraceWarning, "[%!FUNC!] ");
FUNC TraceWarning{FLAGS=TRACE_GENERAL, LEVEL=TRACE_LEVEL_WARNING}(MSG, ...);

USEPREFIX(TraceInfo, "[%!FUNC!] ");
FUNC TraceInfo{FLAGS=TRACE_GENERAL, LEVEL=TRACE_LEVEL_INFORMATION}(MSG, ...);

end_wpp
*/
