from multiprocessing import Process, Event
from pathlib import Path
from time import monotonic
import sys

from pwn import log, args, context, term, pause


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


class WorkerManager:
    def __init__(self, target, workers):
        self._target = target

        self._workers = [None] * workers
        self._success = [None] * workers

        self.__CURRENT_WORKER_ID = None

    def start(self):
        pass

    def stop(self):
        pass

    def sync(self):
        for i, worker in enumerate(self._workers):
            if worker is None:
                # closed_workers_cnt += 1
                self._new_worker(i)

            elif worker.exitcode is not None and worker.exitcode != 0:
                # closed_workers_cnt += 1
                self._new_worker(i)

            elif self._success[i].is_set():
                self.stop()
                return worker

    def _new_worker(self, i):
        self._success[i] = Event()
        self._workers[i] = Process(target=self._worker_wrapper, args=(self._target, i))
        self._workers[i].start()

    def worker_success(self):
        if self.__CURRENT_WORKER_ID is None:
            raise Exception

        self._success[self.__CURRENT_WORKER_ID].set()

        sys.stdout = self.__original_stdout
        sys.stderr = self.__original_stderr
        term.term_mode = self.__original_term_mode
        context.update(log_console=sys.stdout)

    def _worker_wrapper(self, target, number):
        self.__CURRENT_WORKER_ID = number
        self.__original_stdout = sys.stdout
        self.__original_stderr = sys.stderr
        self.__original_term_mode = term.term_mode

        out_path = Path('.pwnbrute')
        out_path.mkdir(parents=True, exist_ok=True)
        worker_stdout_path = out_path / f'worker-{number}.out'
        worker_stdout = open(worker_stdout_path, 'w')

        sys.stdout = sys.stderr = worker_stdout
        term.term_mode = False
        context.update(log_console=worker_stdout)

        target()

        self.worker_success()


workers = None


def success():
    if workers is None:
        return

    workers.worker_success()


def brute(target, k):
    if args.TEST:
        target()
        return

    log.success('PWN Brute started')

    global workers
    workers = WorkerManager(target, k)
    # stats = RunStats()

    while True:
        successed_worker = workers.sync()
        if successed_worker is not None:
            break
