from weakref import WeakKeyDictionary

class StateHandler:
    _states = WeakKeyDictionary()

    def __init__(self, state, obj):
        self._state = state
        self._obj = obj

    def __bool__(self):
        if self._states.get(self._obj, None) is self._state:
            return True
        return False

    def __call__(self):
        self._states[self._obj] = self._state

class State:
    def __get__(self, obj, objtype):
        return StateHandler(self, obj)

class WriteOnceDescriptor:
    def __init__(self):
        self._values = WeakKeyDictionary()

    def __get__(self, obj, objtype):
        return self._values.get(obj, None)

    def __set__(self, obj, value):
        if obj in self._values:
            raise AttributeError('Attribute is write-once')
        self._values[obj] = value

class ClientState:
    CLIENT_CONNECTED = State()
    WAIT_NTLM_NEGOTIATE = State()
    WAIT_NTLM_AUTHENTICATE = State()

    conid = WriteOnceDescriptor()
    msg_challenge = WriteOnceDescriptor()
