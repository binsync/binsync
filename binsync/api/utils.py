import math

import tqdm


def progress_bar(items, gui=True, desc="Progressing..."):
    if gui:
        from binsync.ui.utils import QProgressBarDialog
        pbar = QProgressBarDialog(label_text=desc)
        pbar.show()
        callback_stub = pbar.update_progress
    else:
        t = tqdm.tqdm(desc=desc)
        callback_stub = t.update

    callback_amt = 100 / len(items) if gui else 1

    bucket_size = len(items) / 100.0
    if bucket_size < 1:
        callback_amt = int(1 / (bucket_size))
        bucket_size = 1
    else:
        callback_amt = 1
        bucket_size = math.ceil(bucket_size)

    for i, item in enumerate(items):
        yield item
        if i % bucket_size == 0:
            callback_stub(callback_amt)

    if gui:
        # close the progress bar since it may not hit 100%
        pbar.close()
