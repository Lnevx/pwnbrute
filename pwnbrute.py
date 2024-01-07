from multiprocessing import Process, Event
from pathlib import Path
from time import monotonic
import sys

from pwn import log, args, context, term


class RunStatus:
    _SPEED_RATE = 5

    def __init__(self, rate=1):
        self._rate = rate

        self._progress = log.progress('Status', rate=rate)

        self._prev_time = self._start_time = monotonic()
        self._rate_runs = 0

        self._runs = 0
        self._speed = 'N/A'

    def _print_status(self, printer=None):
        printer(
            f"runs: {self._runs}, "
            f"speed: {self._speed} exec/m"
        )

    def sync(self, status):
        fails, _ = status

        self._runs += fails
        self._rate_runs += fails

        time = monotonic()
        if time - self._prev_time > self._SPEED_RATE:
            self._speed = int(self._rate_runs / (time - self._prev_time) * 60)
            self._prev_time = time
            self._rate_runs = 0

        self._print_status(self._progress.status)

    def stop(self):
        self._print_status(self._progress.success)

        delta = (monotonic() - self._start_time) / 60
        log.success(f"Successfully bruted in {delta:.2f} (min) with {self._runs} runs")


class Worker(Process):
    def __init__(self, *args, worker_id=None, **kwargs):
        self._success_event = Event()
        self._worker_id = worker_id
        self._worker_stdout = None

        out_path = Path('.pwnbrute')
        out_path.mkdir(parents=True, exist_ok=True)
        self._stdout_path = out_path / f'worker-{self._worker_id}.out'

        super().__init__(*args, **kwargs)

    def run(self, *args, **kwargs):
        self.__setup_env()
        super().run(*args, **kwargs)

    def __setup_env(self):
        self.__original_stdout = sys.stdout
        self.__original_stderr = sys.stderr
        self.__original_term_mode = term.term_mode

        self._worker_stdout = open(self._stdout_path, 'w')

        sys.stdout = sys.stderr = self._worker_stdout
        term.term_mode = False
        context.update(log_console=self._worker_stdout)

    def __restore_env(self):
        sys.stdout = self.__original_stdout
        sys.stderr = self.__original_stderr
        term.term_mode = self.__original_term_mode
        context.update(log_console=sys.stdout)

        self._worker_stdout.close()

    def print_output(self):
        log.info('Exploit output:')
        print('-' * 40)
        print(open(self._stdout_path).read().strip())
        print('-' * 40)

    def is_success(self):
        return self._success_event.is_set()

    def set_success(self):
        self._success_event.set()
        self.__restore_env()
        input()


_CURRENT_WORKER = None


class WorkerManager:
    def __init__(self, target, workers):
        self._target = target

        self._workers = [None] * workers
        self._success_worker = None

    def get_success_worker(self):
        return self._success_worker

    def sync(self):
        fails = successes = 0

        for i, worker in enumerate(self._workers):
            if worker is None:
                self._new_worker(i)

            elif worker.exitcode is not None and worker.exitcode != 0:
                fails += 1
                self._new_worker(i)

            elif worker.is_success():
                successes += 1

                self._workers[i] = None
                self._success_worker = worker

                # Stop workers
                for _w in self._workers:
                    if _w is not None:
                        _w.kill()

                break

        return fails, successes

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

    log.info('PWN Brute started')

    global workers
    workers = WorkerManager(target, k)
    run_status = RunStatus()

    while True:
        status = (_, successes) = workers.sync()
        run_status.sync(status)

        if not successes:
            continue

        run_status.stop()
        worker = workers.get_success_worker()
        worker.print_output()

        log.info('Press any key to continue')

        worker.join()
        break
