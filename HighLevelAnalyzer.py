# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from array import array
from email.contentmanager import raw_data_manager
from http.client import SWITCHING_PROTOCOLS
from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting


# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    my_string_setting = StringSetting()
    temp = int()
    data_count_between_data_link_escape = int()
    raw_data_array = []
    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'LT': {
            'format': 'SBU type: {{type}}, data count: {{data.input_type}}'
        },
        'AT': {
            'format': 'SBU type: {{type}}, data count: {{data.input_type}}'
        },
        'RT': {
            'format': 'SBU type: {{type}}, data count: {{data.input_type}}'
        },
        'end': {
            'format': 'SBU type: {{type}}, data count: {{data.input_type}}'
        }

    }

    def __init__(self):
        '''
        Initialize HLA.

        Settings can be accessed using the same name used above.
        '''
        self.data_count_between_data_link_escape = 0
        print("load tbt3 decoder\r\n")

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
                return AnalyzerFrame("end", frame.start_time, frame.end_time, {
                    'input_type': self.temp
                })
            elif self.data_count_between_data_link_escape == 3:
                self.LT_decode()
                self.data_count_between_data_link_escape = 0
                return AnalyzerFrame("LT", frame.start_time, frame.end_time, {
                    'input_type': self.temp
                })
            elif self.data_count_between_data_link_escape == 5:
                self.RT_decode()
                self.data_count_between_data_link_escape = 0
                return AnalyzerFrame("RT", frame.start_time, frame.end_time, {
                    'input_type': self.temp
                })
            else:
                self.data_count_between_data_link_escape = 0
                self.AT_decode()
                return AnalyzerFrame("AT", frame.start_time, frame.end_time, {
                    'input_type': self.temp
                })
        else:
            self.data_count_between_data_link_escape = self.data_count_between_data_link_escape + 1
            self.raw_data_array.append(frame.data['data'])
        # Return the data frame itself

    def LT_decode(self):
        print("LT")
        print('raw_data %x' % self.raw_data_array)

    def RT_decode(self):
        print("RT")
        print('raw_data %x' % self.raw_data_array)

    def AT_decode(self):
        print("AT")
        print('raw_data %x' % self.raw_data_array)
