from functools import wraps

def atomic_git_action(f):
    """
    Assures that any function called with this decorator will execute in-order, atomically, on a single thread.
    This all assumes that the function you are passing is a member of the Client class, which will also have
    a scheduler. This also means that this can only be called after the scheduler is started. This also requires a
    Cache. Generally, just never call functions with this decorator until the Client is done initing.

    This function will also attempt to check the cache for requested data on the same thread the original call
    was made from. If not found, the atomic scheduling is done.

    @param f:   A Client object function
    @return:
    """
    @wraps(f)
    def _atomic_git_action(self: "Client", *args, **kwargs):
        no_cache = kwargs.get("no_cache", False)
        if not no_cache:
            # cache check
            cache_item = self.check_cache_(f, **kwargs)
            if cache_item is not None:
                return cache_item

        # non cache available, queue it up!
        priority = kwargs.get("priority", None) or SchedSpeed.SLOW
        ret_val = self.scheduler.schedule_and_wait_job(
            Job(f, self, *args, **kwargs),
            priority=priority
        )

        if ret_val:
            self._set_cache(f, ret_val, **kwargs)

        return ret_val if ret_val is not None else {}

    return _atomic_git_action

