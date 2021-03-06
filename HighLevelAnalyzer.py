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
    decode_string = str()
    start_time_array = []
    end_time_array = []
    start_time = None
    end_time = None
    frame_flip = int()
    temp = int()
    status = int()
    data_count_between_data_link_escape = int()
    raw_data_array = []
    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'LT': {
            'format': 'transaction: {{data.brief}},{{data.decode}}'
        },
        'AT': {
            'format': 'transaction: {{data.brief}},{{data.decode}}'
        },
        'RT': {
            'format': 'transaction: {{data.brief}},{{data.decode}}'
        },
        'end': {
            'format': 'transaction: {{data.brief}},{{data.decode}}'
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
                self.decode_string = None
                self.decode_string = str()
                self.start_time_array.append(frame.start_time)
                self.end_time_array.clear()
            else:
                stx_symbol = int.from_bytes(
                    self.raw_data_array[0], byteorder='big')
                self.data_count_between_data_link_escape = 0

                if (stx_symbol & 0xc0) == 0x00:
                    self.end_time = frame.start_time
                    self.status = 0
                    self.start_time_array.clear()
                    self.AT_decode()
                    return AnalyzerFrame("AT", self.start_time, self.end_time, {
                        'brief': self.my_frame_string,'decode':self.decode_string
                    })
                elif (stx_symbol & 0xc0) == 0x40:
                    self.end_time = frame.start_time
                    self.status = 1
                    self.start_time_array.clear()
                    self.broadcast_or_addressed_RT_decode()
                    return AnalyzerFrame("RT", self.start_time, self.end_time, {
                        'brief': self.my_frame_string ,'decode':self.decode_string
                    })
                elif (stx_symbol & 0xc0) == 0x80:
                    print(self.raw_data_array)
                    self.status = 2
                    self.LT_decode()
                    self.raw_data_array.clear()
                    temp_string = self.my_frame_string
                    self.start_time = frame.start_time
                    self.my_frame_string = None
                    self.my_frame_string = str()
                    self.start_time_array.append(frame.start_time)
                    return AnalyzerFrame("LT", self.start_time_array.pop(0),self.end_time_array.pop(), {
                        'brief': temp_string,'decode':self.decode_string
                    })

        else:
            self.data_count_between_data_link_escape = self.data_count_between_data_link_escape + 1
            self.raw_data_array.append(frame.data['data'])
            self.end_time_array.append(frame.end_time)
        # Return the data frame itself

    def broadcast_or_addressed_RT_decode(self):
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
        data = [0]*(len(self.raw_data_array)-2)
        
        for x in range(1,len(self.raw_data_array)-2):
            data[x-1] = int.from_bytes(self.raw_data_array[x],byteorder='big')
        if stx_symbol & 0x01:
            self.my_frame_string += ' response'
        else:
            self.my_frame_string += ' command'
        self.my_frame_string += ' index:'
        self.my_frame_string += str((stx_symbol & 0x1e) >> 1)
        if (data[1]& 0x80) == 0x80:
            self.my_frame_string += ' write'
        else:
            self.my_frame_string += ' read'
        self.my_frame_string += ' reg:'
        self.my_frame_string += hex(data[0])

        if data[0] == 0:
            self.my_frame_string += ' vendor id reg'
        elif data[0] == 1:
            self.my_frame_string += ' product id reg'
        elif data[0] == 8:
            self.my_frame_string += ' op code reg'
        elif data[0] == 9:
            self.my_frame_string += ' meta data reg'
        elif data[0] == 12:
            self.my_frame_string += ' link config reg'
        elif data[0] == 13:
            self.my_frame_string += ' Tx FFE reg'
        else:
            self.my_frame_string += ' undefined reg'
 
        self.my_frame_string += ' len:'
        self.my_frame_string += str(data[1])
        self.my_frame_string += ' data:'

        for x in range(2,len(self.raw_data_array)-3):
            self.my_frame_string += hex(data[x])
            self.my_frame_string += ','            
        

    def AT_decode(self):
        self.my_frame_string+= ' AT'
        start_transaction_symbol = int.from_bytes(
            self.raw_data_array[0], byteorder='big')
        data = [0]*(len(self.raw_data_array)-2)
        for x in range(1,len(self.raw_data_array)-2):
            data[x-1] = int.from_bytes(self.raw_data_array[x],byteorder='big')

        if start_transaction_symbol & 1:
            self.my_frame_string += ' command '
        else:
            self.my_frame_string += ' response '

        if start_transaction_symbol & 4:
            self.my_frame_string += ' final recipient '

        if (data[1]& 0x80) == 0x80:
            self.my_frame_string += ' write'
        else:
            self.my_frame_string += ' read'
        self.my_frame_string += ' reg:'
        self.my_frame_string += hex(data[0])

        if data[0] == 0:
            self.my_frame_string += ' vendor id reg'
        elif data[0] == 1:
            self.my_frame_string += ' product id reg'
        elif data[0] == 8:
            self.my_frame_string += ' op code reg'
        elif data[0] == 9:
            self.my_frame_string += ' meta data reg'
        elif data[0] == 12:
            self.my_frame_string += ' link config reg'
            if (len(self.raw_data_array)-2) > 3:
                if (data[1]& 0x01) == 0x1:
                    self.decode_string += ' enable decision lane0'
                if (data[1]& 0x02) == 0x2:
                    self.decode_string += ' enable decision lane1'
                if (data[2]& 0x01) == 0x1:
                    self.decode_string += ' enable request lane0'
                if (data[2]& 0x02) == 0x2:
                    self.decode_string += ' enable request lane1'
                if (data[2]& 0x10) == 0x10:
                    self.decode_string += ' lane Bonding support'
                if (data[2]& 0x20) == 0x20:
                    self.decode_string += ' gen3 support'
                if (data[2]& 0x40) == 0x40:
                    self.decode_string += ' RS-FEC Request Gen2'
                if (data[2]& 0x80) == 0x80:
                    self.decode_string += ' RS-FEC Request Gen3'
                if (data[3]& 0x01) == 0x01:
                    self.decode_string += ' USB4 sideband channel support'
                if (data[3]& 0x02) == 0x02:
                    self.decode_string += ' TBT3 compatible speeds support'                
        elif data[0] == 13:
            self.my_frame_string += ' Tx FFE reg'
        else:
            self.my_frame_string += ' undefined reg'
 
        self.my_frame_string += ' len:'
        self.my_frame_string += str(data[1])
        self.my_frame_string += ' data:'

        for x in range(2,len(self.raw_data_array)-3):
            self.my_frame_string += hex(data[x])
            self.my_frame_string += ','            

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
            self.decode_string += ' USB4'

        if link_parameters_LSB & 0x04:
            self.decode_string += ' RS FEC enabled'

        if link_parameters_LSB & 0x08:
            self.decode_string += ' SSC on'
        else:
            self.decode_string += ' SSC off'

        if link_parameters_HSB & 0x01:
            self.decode_string += ' lane 0 on'

        if link_parameters_HSB & 0x02:
            self.decode_string += ' lane 1 on'

        if (link_parameters_HSB & 0xf0) == 0x10:
            self.decode_string += ' gen 2 speed'
        elif (link_parameters_HSB & 0xf0) == 0x20:
            self.decode_string += ' gen 3 speed'

    def LT_decode(self):
        self.my_frame_string+= ' LT'
        lane_sate_event = int.from_bytes(
            self.raw_data_array[0], byteorder='big')
        if (lane_sate_event & 0x0f) == 0:
            self.my_frame_string += ' LT_FALL'
        elif (lane_sate_event & 0x0f) == 0x02:
            self.my_frame_string += ' LT_RESUME'
        elif (lane_sate_event & 0x0f) == 0x03:
            self.my_frame_string += ' LT_LR_off'
        