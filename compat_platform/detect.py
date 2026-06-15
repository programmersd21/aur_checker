import sys


def detect_color(color_opt: str) -> bool:
    if color_opt == "true":
        return True
    if color_opt == "false":
        return False

    is_tty = sys.stdout.isatty()
    if not is_tty:
        return False

    if sys.platform.startswith("win"):
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.windll.kernel32
            hStdOut = kernel32.GetStdHandle(-11)
            if hStdOut == -1:
                return False
            mode = wintypes.DWORD()
            if not kernel32.GetConsoleMode(hStdOut, ctypes.byref(mode)):
                return False
            ENABLE_VIRTUAL_TERMINAL_PROCESSING = 4
            if not (mode.value & ENABLE_VIRTUAL_TERMINAL_PROCESSING):
                mode.value |= ENABLE_VIRTUAL_TERMINAL_PROCESSING
                if not kernel32.SetConsoleMode(hStdOut, mode):
                    return False
            return True
        except Exception:
            return False
    return True
