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

    callback_amt = math.floor(100 / len(items)) if gui else 1
    for item in items:
        yield item
        callback_stub(callback_amt)

    if gui:
        # close the progress bar since it may not hit 100%
        pbar.close()
