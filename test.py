class Test:
    def __init__(self):
        pass

    def new_callback(self, cb):
        self.callback = cb

    def callback(self):
        pass


t = Test()
t.new_callback(lambda: print('1'))
t.callback()
