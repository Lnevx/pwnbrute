from multiprocessing import Process
from pathlib import Path
from time import monotonic
import sys

from pwn import log, args, context, term


class RunStats:
    def __init__(self, delay=1):
        self._delay = delay

        self._prev_time = monotonic()

        self.runs = self._cur_runs = self.run_time = 0
        self._progress = log.progress('Stat')

    def increase(self):
        self._cur_runs += 1
        self.runs += 1

    def sync(self):
        time = monotonic()
        if time - self._prev_time > self._delay:
            self.run_time += time - self._prev_time
            self._prev_time = time

            self._progress.status(
                f"runs: {self.runs}, "
                f"speed: {int(self._cur_runs / self._delay * 60)} exec/m"
            )
            self._cur_runs = 0

    def finish(self):
        time = monotonic()
        self.run_time += time - self._prev_time
        self._prev_time = time

        self._progress.success(
            f"runs: {self.runs}, "
            f"speed: {int(self._cur_runs / self._delay * 60)} exec/m"
        )


def _wrapper(target, number):
    out_path = Path('.pwnbrute')
    out_path.mkdir(parents=True, exist_ok=True)
    worker_stdout_path = out_path / f'worker-{number}.out'
    worker_stdout = open(worker_stdout_path, 'w')

    sys.stdout = sys.stderr = worker_stdout
    term.term_mode = False

    with context.local(log_console=worker_stdout):
        target()


def brute(target, k):
    if args.TEST:
        target()
        return

    log.success('PWN Brute started')

    workers = [None] * k
    stats = RunStats()

    while True:
        for i, w in enumerate(workers):
            stats.sync()

            if w is None:
                w = Process(target=_wrapper, args=(target, i))
                w.start()
                workers[i] = w
                continue

            if w.exitcode is None:
                continue

            if w.exitcode != 0:
                workers[i] = None

                stats.increase()
                continue

            stats.increase()
            stats.finish()

            w.join()
            workers[i] = None
            for w in filter(None, workers):
                w.kill()

            log.info(
                f'Successfully bruted in {stats.run_time / 60:.2f} min '
                f'({stats.runs} runs)'
            )
            log.info('Output:')

            out_path = Path('.pwnbrute') / f'worker-{i}.out'
            print()
            print(open(out_path).read())
            return
