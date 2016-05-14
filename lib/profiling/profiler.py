import cProfile

def do_profile(func):
    def profiling_func(*args, **kwargs):
        profiler = cProfile.Profile()
        try:
            profiler.enable()
            result = func(*args, **kwargs)
            profiler.disable()
            return result
        finally:
            profiler.print_stats()
    return profiling_func
