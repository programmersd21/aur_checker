import os
import sys


def get_cache_dir() -> str:
    env_cache = os.getenv("AURCHECKER_CACHE_DIR")
    if env_cache:
        return env_cache
    if sys.platform.startswith("win"):
        local_app = os.getenv("LOCALAPPDATA", "")
        return os.path.join(local_app, "aur_checker", "cache")
    elif sys.platform == "darwin":
        return os.path.expanduser("~/Library/Caches/aur_checker")
    else:
        xdg_cache = os.getenv("XDG_CACHE_HOME")
        if xdg_cache:
            return os.path.join(xdg_cache, "aur_checker")
        return os.path.expanduser("~/.cache/aur_checker")
