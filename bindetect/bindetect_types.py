import asn1

class BinDetectProcessor:
    def __init__(self):
        pass

class Asn1Processor(BinDetectProcessor):
    def process(self, file_bytes):
        try:
            # Run through the ASN.1 decoding process. If the file 
            decoder = asn1.Decoder()
            decoder.start(file_bytes)
            while not decoder._end_of_input():
                tag, value = decoder.read()

            return [(0, len(file_bytes))]
        except:
            pass

        return []
