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


class Worker(Process):
    def __init__(self, *args, worker_id=None, **kwargs):
        self._success_event = Event()
        self._worker_id = worker_id
        self._worker_stdout = None

        super().__init__(*args, **kwargs)

    def run(self, *args, **kwargs):
        self.__setup_env()
        super().run(*args, **kwargs)

    def __setup_env(self):
        self.__original_stdout = sys.stdout
        self.__original_stderr = sys.stderr
        self.__original_term_mode = term.term_mode

        out_path = Path('.pwnbrute')
        out_path.mkdir(parents=True, exist_ok=True)
        worker_stdout_path = out_path / f'worker-{self._worker_id}.out'

        self._worker_stdout = open(worker_stdout_path, 'w')

        sys.stdout = sys.stderr = self._worker_stdout
        term.term_mode = False
        context.update(log_console=self._worker_stdout)

    def __restore_env(self):
        sys.stdout = self.__original_stdout
        sys.stderr = self.__original_stderr
        term.term_mode = self.__original_term_mode
        context.update(log_console=sys.stdout)

        self._worker_stdout.close()
        out_path = Path('.pwnbrute')
        output = open(out_path / f'worker-{self._worker_id}.out')

        print(output.read())

    def is_success(self):
        return self._success_event.is_set()

    def set_success(self):
        self._success_event.set()
        self.__restore_env()
        pause()


_CURRENT_WORKER = None


class WorkerManager:
    def __init__(self, target, workers):
        self._target = target
        self._workers = [None] * workers

    def sync(self):
        for i, worker in enumerate(self._workers):
            if worker is None:
                self._new_worker(i)

            elif worker.exitcode is not None and worker.exitcode != 0:
                self._new_worker(i)

            elif worker.is_success():
                self._workers[i] = None

                # Stop workers
                for _w in self._workers:
                    if _w is not None:
                        _w.kill()

                return worker

    def _new_worker(self, i):
        self._workers[i] = Worker(target=self._target, worker_id=i)

        global _CURRENT_WORKER
        _CURRENT_WORKER = self._workers[i]

        self._workers[i].start()


def success():
    if _CURRENT_WORKER is None:
        return

    _CURRENT_WORKER.set_success()


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
        if successed_worker:
            successed_worker.join()
            break
