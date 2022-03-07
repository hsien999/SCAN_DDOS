from functools import wraps
from subprocess import check_output, CalledProcessError
from threading import Thread


async def command(cmd, shell=True) -> str:
    """
    Terminal commands via subprocess
    """
    try:
        res = check_output(cmd, shell=shell)
        return res.decode()
    except (CalledProcessError, UnicodeDecodeError):
        return ""


def daemon_thread(fn):
    """
    Thread wrapper function (decorator)
    """

    @wraps(fn)
    def run(*args, **kwargs):
        t = Thread(target=fn, args=args, kwargs=kwargs, daemon=True)
        t.start()
        return t

    return run
