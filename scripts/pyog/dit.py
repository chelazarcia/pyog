

"""
dit.py

Python interface for Lenel OnGuard DataConduIT API. Prepare to catch COMError and
DITError. Based on Python wmi library (https://pypi.org/project/WMI/) slightly modified \
(pyog._wmii).

:Example:

>>> import pyog
>>> dit = pyog.DIT(server='ms5')  # Connect to DataConduIT host
>>> dit.data_query('select LASTNAME, FIRSTNAME, SSNO from Lnl_Cardholder where ZIP is NULL')
[('Lake', 'Lisa', '234'), ('Gorvachev', 'Mikhail', None), ('Carlitos', 'Muñoz', '456'),
('Carr', 'Brian', None), ('Ehud', 'Barak', None), ('Marchetti', 'Thomas', None),
('Streuben', 'Lisa', None), ('Taksh', 'Mastpur', None), ('Twain', 'Mark', None)]
>>> lisa = dit.data_query('select * from Lnl_Cardholder where ID=1')[0][0]
>>> lisa.LASTNAME
'Lake'
>>> lisa.CITY
'Rome'
>>> lisa.CITY = 'Rochester'
>>> lisa.CITY
'Rochester'

>>> dit.send_event('Time Lapse', source='Quantum Panel')
>>> dit.open_door(panel='3300', reader='CK')

>>> access_watcher = dit.hardware_events(pyog.HWAccessEvent)
>>> while 1:
...     event = access_watcher()
...     print(event)
...
{'AccessResult': 2, 'Alarm': {'Description': 'Granted Access', 'EventParamDescription':
'', 'ID': 1, 'IsActive': False, 'MustAcknowledge': True, 'Priority': 50},
'AreaEnteredID': 0, 'AreaExitedID': 0, 'AssetID': None, 'CardholderEntered': True,
'CardNumber': '258963', 'CommServerHostName': 'MS5', 'Description': 'Access Granted',
'DeviceID': 2, 'Duress': False, 'ElevatorFloor': None, 'EventText': '', 'ExtendedID':
None, 'FacilityCode': None, 'ID': 1, 'IsReadableCard': True, 'IssueCode': None,
'PanelID': 1, 'SecondaryDeviceID': 0, 'SECURITY_DESCRIPTOR': None, 'SegmentID': -1,
'SerialNumber': 1536064546, 'SubType': 0, 'Time': '20180906101430.000000-240',
'TIME_CREATED': '131807168705467252', 'Type': 0}

>>> cardholders_watcher = dit.software_events('Lnl_Cardholder')
>>> while 1:
...     event = cardholders_watcher()
...     print(event)
...
{'ADDR1': None, 'ALLOWEDVISITORS': True, 'BDATE': None, 'BUILDING': 0, 'CITY': None,
'DEPT': 0, 'DIVISION': 0, 'EMAIL': None, 'EXT': None, 'FIRSTNAME': 'Valentina',
'FLOOR': None, 'ID': 314, 'LASTCHANGED': '20180906102317.000000-240', 'LASTNAME':
'Tereshkova', 'LOCATION': 0, 'MIDNAME': None, 'OPHONE': None, 'PHONE': None,
'SECOND_EMAIL': None, 'SSNO': None, 'STATE': None, 'TITLE': 0, 'ZIP': None,
'previous': None}

"""


from pyog import _wmii  # Use when compiling exe
# import _wmii  # Use when running from Python
import win32com
# noinspection PyUnresolvedReferences
from pywintypes import com_error
from re import compile, search
# noinspection PyUnresolvedReferences
from pythoncom import CoInitialize
from sys import exc_info
from functools import partial
from collections import OrderedDict


# Hardware event classes.
#: Events occurring in the physical security system.
HWEvent = "Lnl_SecurityEvent"
#: An event occurring due to the presentation of credentials at a reading device.
HWAccessEvent = "Lnl_AccessEvent"
#: An event that consists of a function executed.
HWFunctionEvent = "Lnl_FunctionExecEvent"
#: An event that indicates a change of status on a device.
HWStatusEvent = "Lnl_StatusChangeEvent"
#: An event that is not card related and not access-related.
HWOtherEvent = "Lnl_OtherSecurityEvent"

# Software event classes.
#: Any object operation
SWOperationEvent = "__InstanceOperationEvent"
#: Object creation
SWCreationEvent = "__InstanceCreationEvent"
#: Object modification
SWModificationEvent = "__InstanceModificationEvent"
#: Object deletion
SWDeletionEvent = "__InstanceDeletionEvent"


_COMI_ERROR = (com_error, _wmii.x_wmi)


class WMIDate(str):
    """
    Dummy class to wrap WMI date time strings.
    """
    pass


# WMI types mapping to python types.
# See https://bit.ly/2PTdv3C,
# https://www.magnumdb.com/search?q=parent:WbemCimtypeEnum
#: CYM types mapping to Python.
CIM_PYTYPES = {
    2: int,
    3: int,
    4: int,
    5: int,
    8: str,
    11: bool,
    13: type,
    16: int,
    17: int,
    18: int,
    19: int,
    20: int,
    21: int,
    101: WMIDate,  # str,
    102: type,
    103: str
}


# region: Status

class HWStatus(OrderedDict):
    """
    Extended by private status classes in module, but can also be inherited for custom \
    status containers.
    """

    def decode(self, status: int):
        """
        Decodes status numerically.

        :param status: {int} The (ORed) encoded status.
        :return: {list{int}} Each individual status.
        """
        return [self[code] for code in self if code & status or code == 0]


class _DeviceStatus(HWStatus):

    def __init__(self):
        super().__init__([
            (0x1, 'ONLINE_STATUS'),
            (0x2, 'OPTIONS_MISMATCH_STATUS'),
            (0x4, 'CABINET_TAMPER'),
            (0x8, 'POWER_FAIL')
        ])


class _PanelStatus(_DeviceStatus):
    """
    ISC

    .
    """

    def __init__(self):
        super().__init__()
        self[0x10] = 'DOWNLOADING_FIRMWARE'


class _AlarmPanelStatus(_DeviceStatus):
    """
    Alarm input or output control module

    .
    """

    pass


class _ReaderStatus(HWStatus):

    def __init__(self):
        super().__init__([
            (0x1, 'RDRSTATUS_ONLINE'),
            (0x2, 'RDRSTATUS_OPTION_MISTMATCH'),
            (0x4, 'RDRSTATUS_CNTTAMPER'),
            (0x8, 'RDRSTATUS_PWR_FAIL'),
            (0x10, 'RDRSTATUS_TAMPER'),
            (0x20, 'RDRSTATUS_FORCED'),
            (0x40, 'RDRSTATUS_HELD '),
            (0x80, 'RDRSTATUS_AUX '),
            (0x100, 'RDRSTATUS_AUX2'),
            (0x400, 'RDRSTATUS_AUX3'),
            (0x800, 'RDRSTATUS_BIO_VERIFY'),
            (0x1000, 'RDRSTATUS_DC_GND_FLT'),
            (0x2000, 'RDRSTATUS_DC_SHRT_FLT'),
            (0x4000, 'RDRSTATUS_DC_OPEN_FLT'),
            (0x8000, 'RDRSTATUS_DC_GEN_FLT'),
            (0x10000, 'RDRSTATUS_RX_GND_FLT'),
            (0x20000, 'RDRSTATUS_RX_SHRT_FLT'),
            (0x40000, 'RDRSTATUS_RX_OPEN_FLT'),
            (0x80000, 'RDRSTATUS_RX_GEN_FLT'),
            (0x100000, 'RDRSTATUS_FIRST_CARD_UNLOCK'),
            (0x200000, 'RDRSTATUS_EXTENDED_HELD_MODE'),
            (0x400000, 'RDRSTATUS_CIPHER_MODE'),
            (0x800000, 'RDRSTATUS_LOW_BATTERY'),
            (0x1000000, 'RDRSTATUS_MOTOR_STALLED'),
            (0x2000000, 'RDRSTATUS_READHEAD_OFFLINE'),
            (0x4000000, 'MRDT_ORDRSTATUS_MRDT_OFFLINEFFLINE'),
            (0x8000000, 'RDRSTATUS_DOOR_CONTACT_OFFLINE')
        ])


class _OutputStatus(HWStatus):

    def __init__(self):
        super().__init__()
        self[0x0] = 'ALRM_STATUS_SECURE'
        self[0x1] = 'ALRM_STATUS_ACTIVE '

    def decode(self, status: int):
        return [self[status]]


class _InputStatus(_OutputStatus):

    def __init__(self):
        super().__init__()
        self[0x2] = 'ALRM_STATUS_GND_FLT'
        self[0x3] = 'ALRM_STATUS_SHRT_FLT'
        self[0x4] = 'ALRM_STATUS_OPEN_FLT'
        self[0x5] = 'ALRM_STATUS_GEN_FLT'
        self[0x100] = 'ALRM_STATUS_MASKED'


class _ReaderMode(OrderedDict):

    def __init__(self):
        super().__init__([
            (0x0, 'MODE_LOCKED'),
            (0x1, 'MODE_CARDONLY'),
            (0x2, 'MODE_PIN_OR_CARD'),
            (0x3, 'MODE_PIN_AND_CARD'),
            (0x4, 'MODE_UNLOCKED'),
            (0x5, 'MODE_FACCODE_ONLY'),
            (0x6, 'MODE_CYPHERLOCK'),
            (0x7, 'MODE_AUTOMATIC'),
        ])


#:
PANEL_STATUS = _PanelStatus()
#:
ALARM_PANEL_STATUS = _AlarmPanelStatus()
#:
READER_STATUS = _ReaderStatus()
#:
OUTPUT_STATUS = _OutputStatus()
#:
INPUT_STATUS = _InputStatus()
#:
READER_MODE = _ReaderMode()
_status_cls = {
    'Lnl_Panel': PANEL_STATUS,
    'Lnl_AlarmPanel': ALARM_PANEL_STATUS,
    'Lnl_Reader': READER_STATUS,
    'Lnl_AlarmInput': INPUT_STATUS,
    'Lnl_AlarmOutput': OUTPUT_STATUS,
    'Lnl_ReaderInput': INPUT_STATUS,
    'Lnl_ReaderInput1': INPUT_STATUS,
    'Lnl_ReaderInput2': INPUT_STATUS,
    'Lnl_ReaderOutput': OUTPUT_STATUS,
    'Lnl_ReaderOutput1': OUTPUT_STATUS,
    'Lnl_ReaderOutput2': OUTPUT_STATUS,
}


def decode_status(device, dit_status):
    """
    Decodes numeric hardware status.

    :param device: {DITElement} The hardware device whose status will be decoded.
    :param dit_status: {int} The status retrieved by DataConduIT GetHardwareStatus().
    :return: {list{str}} A list with descriptive string(s) for device status.
    """
    device_cls = device.wmi_class()
    if device_cls in _status_cls:
        status_dic = _status_cls[device_cls]
    else:
        for parent_cls in device.derivation():
            if parent_cls in _status_cls:
                status_dic = _status_cls[parent_cls]
                break
        else:
            raise ValueError(f'Unknown hardware device "{device_cls}"')

    return status_dic.decode(dit_status)

# endregion: Status


class COMError(Exception):
    """
    pywintypes.com_error with added details.
    """
    def __init__(self):
        super().__init__()

        err = exc_info()[1]  # See http://timgolden.me.uk/pywin32-docs/com_error.html
        try:
            hresult, strerror, excepinfo, _ = err.args  # pywintypes.com_error
        except ValueError:
            hresult, strerror, excepinfo, _ = err.com_error.args  # _wmii.x_wmi
        if excepinfo:
            self.source = excepinfo[1]
            self.description = excepinfo[2]
        else:
            self.source = ""
            self.description = strerror

        self.code = hex(_wmii.signed_to_unsigned(hresult))
        self.operation = ""  # To be assigned by client if desired.
        self.param_info = ""
        self.additional_info = excepinfo
        self.handle = err
        self.args = self.code, self.description, self.source, self.param_info


class DITError(COMError):
    """
    _wmii._wmi_object with error info from DataConduIT. See dit_error_info().

    :param dit_err: {_wmii._wmi_object} Error info from DataConduIT.
    """

    _stat_code_re = compile(r"(?<=StatusCode = )\d+")

    def __init__(self, dit_err):
        super().__init__()

        if dit_err.Operation:
            self.source = dit_err.Operation
        self.param_info = dit_err.ParameterInfo
        if dit_err.Description:
            self.description = dit_err.Description
        try:
            # Must call GetObjectText_() because _wmii._wmi_object.StatusCode returns
            # different code than _wmii._wmi_object.GetObjectText_() and DataConduIT log.
            self.code = hex(
                int(search(DITError._stat_code_re, dit_err.GetObjectText_()).group())
            )
        except AttributeError:
            pass
        self.handle = dit_err  # Raw _wmii._wmi_object
        self.args = self.code, self.description, self.source, self.param_info


class DITElement(_wmii._wmi_object):
    """
    Wrapper for DataConduIT objects, except events. Automatically handles committing. \
    lnl_class or ole_obj must be provided.

    :param connection: {DITConnection} The DataConduIT connection. It's namespace is \
    extracted. _wmii._wmi.namespace is also accepted.
    :param lnl_class: {str} DataConduIT class to instantiate. If specified, ole_obj \
    parameter will be disregarded.
    :param ole_obj: {ISWbemObject} OLE object.
    :param kwargs: Named properties to be set upon initialization.
    """

    _cls_re = compile(r"(?<=instance of ).+")

    def __init__(
        self,
        connection,
        lnl_class="",
        ole_obj=None,
        **kwargs
    ):
        """
        lnl_class or ole_obj must be provided

        :param connection: {DITConnection} The DataConduIT connection. It's namespace is
        extracted. _wmii._wmi.namespace is also accepted.
        :param lnl_class: {str} DataConduIT class to instantiate. If specified, ole_obj
        parameter will be disregarded.
        :param ole_obj: {ISWbemObject} OLE object.
        :param kwargs: Named properties to set upon initialization.
        """
        if isinstance(connection, DITConnection):
            connection = connection.namespace
        try:
            ole_object = connection.Get(lnl_class).SpawnInstance_() if lnl_class else \
                ole_obj
            super().__init__(ole_object)
        except _COMI_ERROR:
            handle_error()
        self.__dict__["_namespace"] = connection
        if ole_obj is None:  # Prevents infinite recursion when called from  __refresh()
            self.set(**kwargs)

    def set(self, **kwargs):
        """
        Sets properties in batch.

        :param kwargs: Named properties and values.
        :return: None.
        """
        try:
            super().set(**kwargs)
        except _COMI_ERROR:
            handle_error()
        self._commit()

    def wmi_class(self):
        """
        The DataConduIT class of the wrapped object.

        :return: {str} The wrapped object class.
        """
        return search(DITElement._cls_re, self.GetObjectText_()).group(0)

    def _commit(self):
        """
        Saves changes to DataConduIT

        Must be called when changes are made.
        :return: None.
        """
        obj_path = self.Path_.Path
        if obj_path:
            # Renew members with updated properties.
            self.__refresh(obj_path)
        else:
            try:
                # SWbemObject.Put_() returns SWbemObjectPath on success.
                obj_path = self.Put_().Relpath  # Better than .Path because when
                # connected to cluster .Path contains virtual cluster hostname while
                # the actual path has the active node hostname.
            except _COMI_ERROR:
                handle_error()
            # SWbemObject.Put_() succeeded. Renew members with updated properties.
            self.__refresh(obj_path)

    def __refresh(self, obj_path: str):
        """
        Updates the current instance with properties of fresh instance from DataConduIT

        Must be called after saving changes to DataConduIT to get the updated object.
        :param obj_path: {str} Object WMI path.
        :return: None.
        """
        try:
            new_obj = self._namespace.Get(obj_path)
        except _COMI_ERROR:
            handle_error()
        # noinspection PyUnboundLocalVariable
        self.__dict__.update(DITElement(self._namespace, ole_obj=new_obj).__dict__)

    def __setattr__(self, key, value):
        # If path exists  _wmii._wmi_object.__setattr__() will call SWbemObject.Put_().
        try:
            super().__setattr__(key, value)
        except _COMI_ERROR:
            handle_error()
        self._commit()


class _DITWatcher(_wmii._wmi_watcher):
    """
    DataConduIT events watcher

    Call instance to receive events when they arrive. Note that this blocks until
    event arrival.
    """

    def __init__(self, connection: _wmii._wmi_namespace,
                 notification_wql,
                 is_extrinsic):
        """
        :param connection: {_wmii._wmi_namespace} DataConduIT namespace connection.
        :param notification_wql: {str} WQL notification expression.
        :param is_extrinsic: {bool} Whether the events to watch for are extrinsic.
        Hardware events are extrinsic while software events are intrinsic.
        """
        try:
            wmi_event = connection.ExecNotificationQuery(notification_wql)
        except _COMI_ERROR:
            handle_error()
        else:
            super().__init__(
                wmi_event=wmi_event,
                is_extrinsic=is_extrinsic
            )

    @staticmethod
    def _to_dict(wmi_obj) -> dict:
        """
        Converts event instance properties and values to dict

        :param wmi_obj: {_wmii._wmi_object} Event instance.
        :return: {dict} Properties and values mapped to dict.
        """
        return {p.Name: p.Value for p in wmi_obj.Properties_}

    def __call__(self, *args, **kwargs):
        """
        Waits for an event to arrive and delivers it

        :return: {dict} A dict with the events properties and values. "previous" key
        contains the previous state of the instance if available.
        """
        try:
            return super().__call__()
        except _COMI_ERROR:
            handle_error()


class HWatcher(_DITWatcher):
    """
    Watches for hardware events and delivers them as a dictionary when called.

    :param connection: {_wmii._wmi_namespace} DataConduIT namespace connection.
    :param EventClass: {str} The name of the hardware event class to watch for.

    DataConduIT hardware events hierarchy:

    * Lnl_Event(__ExtrinsicEvent) >

                                    * Lnl_SecurityEvent >

                                                          * Lnl_AccessEvent
                                                          * Lnl_FireEvent
                                                          * Lnl_FunctionExecEvent
                                                          * Lnl_IntercomEvent
                                                          * Lnl_OtherSecurityEvent
                                                          * Lnl_StatusChangeEvent
                                                          * Lnl_TransmitterEvent
                                                          * Lnl_VideoEvent
    """

    def __init__(self, connection, EventClass):
        super().__init__(
            connection,
            f"SELECT * FROM {EventClass}",
            is_extrinsic=True
        )

    def __call__(self, *args, **kwargs) -> dict:
        """
        Waits for an event to arrive and delivers it. Note that this is blocking.

        :return: {dict} A dict with the events properties and values.
        """
        dict_evt = _DITWatcher._to_dict(super().__call__())
        dict_evt["Alarm"] = _DITWatcher._to_dict(dict_evt["Alarm"])
        return dict_evt


class SWatcher(_DITWatcher):
    """
    Watches for software events and delivers them as a dictionary when called.

    The following classes are supported for software event registration:
    Lnl_Cardholder, Lnl_Visitor, Lnl_Badge, and Lnl_Account (Directory accounts linked
    to Cardholder).

    :param connection: {_wmii._wmi_namespace} DataConduIT namespace connection.
    :param SWClass: {str} The name of software class to watch changes for.
    :param operation: The operation type class to watch for: __InstanceOperationEvent or\
    child.

    WMI software event operation hierarchy:

    * __InstanceOperationEvent >

                                * __InstanceCreationEvent
                                * __InstanceModificationEvent
                                * __InstanceDeletionEvent
    """

    targets = ('lnl_cardholder', 'lnl_visitor', 'lnl_badge', 'lnl_account')

    def __init__(self, connection, TargetCls, operation):
        if TargetCls.lower() not in SWatcher.targets:
            raise ValueError(f'Invalid target class: {TargetCls}')
        super().__init__(
            connection,
            f"select * from {operation} where TargetInstance ISA '{TargetCls}'",
            is_extrinsic=False
        )

    def __call__(self, *args, **kwargs):
        """
        Waits for an event to arrive and delivers it. Note that this is blocking.

        :return: {dict} A dict with the events properties and values. "previous" key
        contains the previous state of the instance if available.
        """
        event = super().__call__()
        dict_evt = _DITWatcher._to_dict(event)
        dict_evt["previous"] = _DITWatcher._to_dict(event.previous) \
            if event.previous is not None else None
        return dict_evt


class DITConnection:
    """
    OnGuard WMI namespace connection manager. Can be instantiated directly but use
    DIT() for convenience.
    """

    def __init__(self, dit_namespace: _wmii._wmi_namespace):
        self._namespace = dit_namespace

    @property
    def namespace(self) -> _wmii._wmi_namespace:
        """
        The raw wmi namespace connection.

        :return: {wmi._wmi_namespace} The raw WMI namespace connection.
        """
        return self._namespace

    def data_query(self, wql: str) -> list:
        """
        Runs a WQL data query (as opposed to an event or schema query).

        :param wql: {str} The query.
        :return: {list{tuple}} If queried for "*" a list of tuples with DITElements,\
        otherwise a list of tuples with the specified properties.
        """
        try:
            results = self._namespace.query(wql)
            properties = [p.strip()
                          for p in wql[7:wql.lower().index(' from')].split(',')]
            if properties[0] == '*':
                return [tuple(DITElement(self._namespace, ole_obj=r) for r in results)]
            else:
                final_results = []
                for r in results:
                    final_results.append(
                        tuple(getattr(r, p.upper()) for p in properties)
                    )
                return final_results
        except _COMI_ERROR:
            handle_error()

    def open_door(self, panel, reader):
        """
        Pulses reader open.

        :param panel: {str} Panel name upstream the reader.
        :param reader: {str} Reader name.
        :return: None.
        """
        panel_id = self.data_query(f'select ID from Lnl_Panel where NAME = "{panel}"')
        if panel_id:
            lnl_reader = self.data_query(
                f'select * from Lnl_Reader '
                f'where PanelID = {panel_id[0][0]} and Name = "{reader}"'
            )
            if lnl_reader:
                lnl_reader[0][0].OpenDoor()
            else:
                DITConnection._not_found_error("panel", panel)
        else:
            DITConnection._not_found_error("reader", reader)

    def hardware_events(self, EventClass=HWEvent):
        """
        Creates hardware event subscription for the given event class.

        :param EventClass: {str} The hardware event class.
        :return: {HWatcher} The hardware event watcher.
        """
        return HWatcher(self._namespace, EventClass)

    def software_events(self, TargetCls, operation=SWOperationEvent):
        """
        Creates software event subscription for the given event class and operation.

        :param TargetCls: {str} The software event class.
        :param operation: {str} The operation type. __InstanceOperationEvent or child.
        :return: {SWatcher} The software event watcher.
        """
        return SWatcher(self._namespace, TargetCls, operation)

    def send_access_granted(self, panel, reader, badge_id=-1):
        """
        Access granted.

        If sent for a logical panel, reader is optional. Reader must be specified if \
        sending for physical panel.

        :param panel: {str} Panel name.
        :param reader: {str} Reader name.
        :param badge_id: {int} Badge number. Default sends no badge.
        :return: None.
        """
        self.send_event(description="",
                        source=panel,
                        device=reader,
                        IsAccessGrant=True,
                        BadgeID=False if badge_id == -1 else badge_id
                        )

    def send_access_denied(self, panel, reader, badge_id=-1):
        """
        Access denied.

        If sent for a logical panel, reader is optional. Reader must be specified if
        sending for physical panel.

        :param panel: {str} Panel name.
        :param reader: {str} Reader name.
        :param badge_id: {int} Badge number. Default sends no badge.
        :return: None.
        """
        self.send_event(description="",
                        source=panel,
                        device=reader,
                        IsAccessDeny=True,
                        BadgeID=False if badge_id == -1 else badge_id
                        )

    def send_event(self, description, source, device="", subdevice="", **kwargs):
        """
        Sends logical appliance event.

        Only logical appliances are supported. Source, device and subdevice form a
        hierarchy so the parent must be specified in order for its child to be found.

        :param description: {str} Event description.
        :param source: {str} Source name.
        :param device: {str} Device name.
        :param subdevice: {str} Subdevice name.
        :param kwargs: See the DataConduIT Guide for supported named arguments.
        :return: None.
        """
        try:
            self._namespace.Lnl_IncomingEvent.SendIncomingEvent(
                Source=source,
                Device=device,
                SubDevice=subdevice,
                Description=description,
                **kwargs
            )
        except _COMI_ERROR:
            handle_error()

    @staticmethod
    def _not_found_error(obj, qualifier):
        raise _wmii.x_wmi(f'{obj} "{qualifier}" not found.')


def _connect_dit(
        server=".",
        username="",
        password="",
        coinitialize=False
    ) -> DITConnection:
    """
    Creates a connection manager to OnGuard namespace.

    :param server: {str} Hostname (IP can cause problems).
    :param username: {str} Username.
    :param password: {str} User password.
    :param coinitialize: {bool} Initializes the COM libraries for the current thread. \
    Use when connection is not made from the main thread. Note that COM objects can only
    be edited in the thread where they were created or acquired.
    :return: {_wmii._wmi_namespace} The connection instance.
    """
    # Username in format domain\user.
    try:
        # This mus occur before touching COMM objects.
        if coinitialize:
            CoInitialize()
        # noinspection PyUnresolvedReferences
        locator = win32com.client.Dispatch("WbemScripting.SWbemLocator")
        # Using IP leads to problems.
        wbemsvc = locator.ConnectServer(server, "Root\\OnGuard", username, password)
        conn = _wmii.WMI(wmi=wbemsvc)
    except _COMI_ERROR:
        handle_error()
    else:
        return DITConnection(conn)


DIT = _connect_dit


def dit_error_info() -> _wmii._wmi_object:
    """
    Retrieves information for last DataConduIT error.

    :return: {_wmii._wmi_object} SWbemLastError child with DataConduIT error information.
    """
    # noinspection PyUnresolvedReferences
    try:
        # Get last WMI/DataConduIT error.
        # noinspection PyUnresolvedReferences
        dc_e = win32com.client.Dispatch("WbemScripting.SWbemLastError")
    except com_error:
        # No error info was received from DataConduIT.
        pass
    else:
        return _wmii._wmi_object(dc_e)  # Child of Lnl_Error.


def handle_error() -> None:
    """
    Exception handler that extracts exception information from DataConduIT.

    :raises DITError: If DataConduIT has error information.
    :raises COMError: If DataConduIT doesn't have error information.
    """
    err = dit_error_info()  # See if DataConduIT returned error info.
    if err:
        cls = partial(DITError, err)
    else:
        # DataConduIT did not return error info.
        cls = partial(COMError)
    raise cls()


if __name__ == '__main__':
    pass
