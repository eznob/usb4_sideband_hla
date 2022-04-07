# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from array import array
from email.contentmanager import raw_data_manager
from http.client import SWITCHING_PROTOCOLS
from tokenize import String
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    my_frame_string = str()
    start_time = None
    end_time = None
    frame_flip = int()
    temp = int()
    data_count_between_data_link_escape = int()
    raw_data_array = []
    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'LT': {
            'format': 'SBU type: {{type}}, command decode: {{data.input_type}}'
        },
        'AT': {
            'format': 'SBU type: {{type}}, command decode: {{data.input_type}}'
        },
        'RT': {
            'format': 'SBU type: {{type}}, command decode: {{data.input_type}}'
        },
        'end': {
            'format': 'SBU type: {{type}}, command decode: {{data.input_type}}'
        }

    }

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''
        self.frame_flip = 0
        self.data_count_between_data_link_escape = 0

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.

        The type and data values in `frame` will depend on the input analyzer.
        '''
        if frame.data['data'] == b'\xfe':
            self.temp = self.data_count_between_data_link_escape
            if self.data_count_between_data_link_escape <= 1:
                self.data_count_between_data_link_escape = 0
                self.raw_data_array.clear()
                self.start_time = frame.start_time
                self.my_frame_string = None
                self.my_frame_string = str()
                return AnalyzerFrame("end", frame.start_time, frame.end_time, {
                    'input_type': self.temp
                })
            else:
                stx_symbol = int.from_bytes(
                    self.raw_data_array[0], byteorder='big')
                self.data_count_between_data_link_escape = 0
                self.end_time = frame.start_time

                if (stx_symbol & 0xc0) == 0x00:
                    self.AT_decode()
                    return AnalyzerFrame("AT", self.start_time, self.end_time, {
                        'input_type': self.my_frame_string
                    })
                elif (stx_symbol & 0xc0) == 0x40:
                    self.broadcast_or_addressed_RT_decode()
                    return AnalyzerFrame("RT", frame.start_time, frame.end_time, {
                        'input_type': self.my_frame_string
                    })
                elif (stx_symbol & 0xc0) == 0x80:
                    self.LT_decode()
                    return AnalyzerFrame("LT", frame.start_time, frame.end_time, {
                        'input_type': self.my_frame_string
                    })

        else:
            self.data_count_between_data_link_escape = self.data_count_between_data_link_escape + 1
            self.raw_data_array.append(frame.data['data'])
        # Return the data frame itself

    def broadcast_or_addressed_RT_decode(self):
        print('RT')
        stx_symbol = int.from_bytes(
            self.raw_data_array[0], byteorder='big')
        if (stx_symbol & 0x20) == 0x20:
            self.RT_decode()
        else:
            self.addressed_RT_decode()

    def addressed_RT_decode(self):
        self.my_frame_string+= ' addressed RT'
        stx_symbol = int.from_bytes(
            self.raw_data_array[0], byteorder='big')
        if stx_symbol & 0x01:
            self.my_frame_string += ' RT response'
        else:
            self.my_frame_string += ' RT command'
        self.my_frame_string += ' index:'
        self.my_frame_string += str((stx_symbol & 0x1e) >> 1)

    def AT_decode(self):
        start_transaction_symbol = int.from_bytes(
            self.raw_data_array[0], byteorder='big')
        if start_transaction_symbol & 1:
            self.my_frame_string += ' AT command '
        else:
            self.my_frame_string += ' AT response '
        if start_transaction_symbol & 4:
            self.my_frame_string += ' AT final recipient '

    def RT_decode(self):
        self.my_frame_string+= ' broadcast RT'
        start_transaction_symbol = int.from_bytes(
            self.raw_data_array[0], byteorder='big')
        link_parameters_LSB = int.from_bytes(
            self.raw_data_array[1], byteorder='big')
        link_parameters_HSB = int.from_bytes(
            self.raw_data_array[2], byteorder='big')
        if start_transaction_symbol & 1:
            self.my_frame_string += ' RT command'
        else:
            self.my_frame_string += ' RT response'
        if start_transaction_symbol & 0x20:
            self.my_frame_string += ' RT broadcast'
        if link_parameters_LSB & 0x01:
            self.my_frame_string += ' USB4'
        if link_parameters_LSB & 0x04:
            self.my_frame_string += ' RS FEC enabled'
        if link_parameters_LSB & 0x08:
            self.my_frame_string += ' SSC on'
        else:
            self.my_frame_string += ' SSC off'
        if link_parameters_HSB & 0x01:
            self.my_frame_string += ' lane 0 on'
        if link_parameters_HSB & 0x02:
            self.my_frame_string += ' lane 1 on'
        if (link_parameters_HSB & 0xf0) == 0x10:
            self.my_frame_string += ' gen 2 speed'
        elif (link_parameters_HSB & 0xf0) == 0x20:
            self.my_frame_string += ' gen 3 speed'
        print(self.my_frame_string)

    def LT_decode(self):
        lane_sate_event = int.from_bytes(
            self.raw_data_array[0], byteorder='big')
        if (lane_sate_event & 0x0f) == 0:
            self.my_frame_string += ' LT_FALL'
        elif (lane_sate_event & 0x0f) == 0x02:
            self.my_frame_string += ' LT_RESUME'
        elif (lane_sate_event & 0x0f) == 0x03:
            self.my_frame_string += ' LT_LR_off'
