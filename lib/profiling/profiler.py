import cProfile, pstats

def do_profile(func):
    def profiling_func(*args, **kwargs):
        profiler = cProfile.Profile()
        try:
            profiler.enable()
            result = func(*args, **kwargs)
            profiler.disable()
            return result
        finally:
            sortkey = 'tottime'
            result = pstats.Stats(profiler).sort_stats(sortkey)
            result.print_stats()
    return profiling_func
