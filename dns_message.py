#!/usr/bin/python3

from enum import IntEnum


class IncorrectQuery(Exception):
    pass


class MessageType(IntEnum):
    QUERY = 0
    RESPONSE = 1


class RecordType(IntEnum):
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    HINFO = 13
    MX = 15
    AAAA = 28
    AXFR = 252
    ANY = 255


def read_name(data, ind):
    name = ""
    while data[ind] != 0:
        if (data[ind] & 0b11000000) == 0b11000000:
            ind = ((data[ind] & 0b00111111) * 2 ** 8 +
                   data[ind + 1])
        name_length = data[ind]
        ind += 1
        for __ in range(name_length):
            name += chr(data[ind])
            ind += 1
        name += "."
    ind += 1
    return name, ind


class DNSQuestion:
    def __init__(self, name="", request_type=0, request_class=0):
        self.name = name
        self.request_type = request_type
        self.request_class = request_class

    def to_bytes(self, last_data: bytearray) -> bytearray:
        lengths = iter(map(len, self.name.split(".")))
        name = bytearray()
        name.append(next(lengths))
        for ch in self.name:
            if ch != '.':
                name.append(ord(ch))
            else:
                name.append(next(lengths))
        name_in_data = last_data.find(name)
        if name_in_data != -1:
            name = bytearray(2)
            name[0] = 0b11000000 | (name_in_data & (255 << 8))
            name[1] = name_in_data & 255
        result = bytearray(name)
        result += bytearray([(self.request_type & (255 << 8)) >> 8,
                             self.request_type & 255,
                             (self.request_class & (255 << 8)) >> 8,
                             self.request_class & 255])
        return result

    @staticmethod
    def from_bytes(data: bytearray, start_ind: int, count_questions: int):
        i = start_ind
        questions = []
        try:
            for _ in range(count_questions):
                curr_question = DNSQuestion()
                if (data[i] & 0b11000000) == 0b11000000:
                    j = (data[i] & 0b00111111) * 2 ** 8 + data[i + 1]
                    i += 2
                    curr_question.name, _ = read_name(data, j)
                else:
                    curr_question.name, i = read_name(data, i)
                curr_question.request_type = RecordType(
                    data[i] * 2 ** 8 + data[i + 1])
                curr_question.request_class = data[i + 2] * 2 ** 8 + data[i + 3]
                i += 4
                questions.append(curr_question)
        except (ValueError, IndexError):
            raise IncorrectQuery
        return questions, i


class DNSResourceRecord:
    def __init__(self, name="", request_type=0,
                 request_class=0, ttl=0, data_len=0, data=None):
        self.name = name
        self.request_type = request_type
        self.request_class = request_class
        self.ttl = ttl
        self.data_len = data_len
        self.data = data

    @staticmethod
    def from_bytes(data: bytearray, start_ind: int, count_record: int):
        i = start_ind
        records = []
        try:
            for _ in range(count_record):
                curr_record = DNSResourceRecord()
                if (data[i] & 0b11000000) == 0b11000000:
                    j = (data[i] & 0b00111111) * 2 ** 8 + data[i + 1]
                    i += 2
                    curr_record.name, _ = read_name(data, j)
                else:
                    curr_record.name, i = read_name(data, i)
                curr_record.request_type = RecordType(
                    data[i] * 2 ** 8 + data[i + 1])
                curr_record.request_class = data[i + 2] * 2 ** 8 + data[i + 3]
                i += 4
                curr_record.ttl = (data[i] * 2 ** 24 + data[i + 1] * 2 ** 16 +
                                   data[i + 2] * 2 ** 8 + data[i + 3])
                i += 4
                curr_record.data_len = (data[i] * 2 ** 8 + data[i + 1])
                i += 2
                if (curr_record.request_type == RecordType.A and
                        curr_record.data_len == 4):
                    curr_record.data = data[i:i + curr_record.data_len]
                else:
                    curr_record.data = data[i:i + curr_record.data_len]
                records.append(curr_record)
                i += curr_record.data_len
        except (ValueError, IndexError):
            raise IncorrectQuery
        return records, i

    def to_bytes(self, last_data: bytearray) -> bytearray:
        lengths = iter(map(len, self.name.split(".")))
        name = bytearray()
        name.append(next(lengths))
        for ch in self.name:
            if ch != '.':
                name.append(ord(ch))
            else:
                name.append(next(lengths))
        name_in_data = last_data.find(name)
        if name_in_data != -1:
            name = bytearray(2)
            name[0] = 0b11000000 | (name_in_data & (255 << 8))
            name[1] = name_in_data & 255
        return bytearray(name) + bytearray(
            [(int(self.request_type) & (255 << 8)) >> 8,
             int(self.request_type) & 255,
             (self.request_class & (255 << 8)) >> 8,
             self.request_class & 255,
             (self.ttl & (255 << 24)) >> 24,
             (self.ttl & (255 << 16)) >> 16,
             (self.ttl & (255 << 8)) >> 8,
             self.ttl & 255,
             (self.data_len & (255 << 8)) >> 8,
             self.data_len & 255]) + self.data


class DNSMessage:
    def __init__(self, id=0, response_type=0, opcode=0,
                 is_authoritative_answer=False, is_truncated=False,
                 is_recursion_desired=False, is_recursion_acailable=0,
                 return_code=0, answers=None, questions=None,
                 auth_servers=[], addit_records=[]):
        self.id = id
        self.response_type = response_type
        self.opcode = opcode
        self.is_authoritative_answer = is_authoritative_answer
        self.is_truncated = is_truncated
        self.is_recursion_desired = is_recursion_desired
        self.is_recursion_available = is_recursion_acailable
        self.return_code = return_code
        self.answers = answers
        self.questions = questions
        self.auth_servers = auth_servers
        self.addit_records = addit_records

    @staticmethod
    def make_answer(question, cash_answers):
        answer = DNSMessage(id=question.id, response_type=1,
                            opcode=question.opcode,
                            is_authoritative_answer=False,
                            is_truncated=False,
                            is_recursion_desired=True,
                            is_recursion_acailable=True,
                            return_code=question.return_code,
                            questions=question.questions)
        answer.answers = list(map(
            lambda answer: DNSResourceRecord(
                name=question.questions[0].name,
                request_type=question.questions[0].request_type,
                request_class=question.questions[0].request_class,
                ttl=300,
                data_len=len(answer.data),
                data=bytearray(answer.data)), cash_answers))
        return answer

    def __hash__(self):
        return hash(sum(self.id))

    def from_bytes(self, data: bytearray):
        try:
            if len(data) < 12:
                raise IncorrectQuery
            self.id = data[:2]
            flags = data[2:4]
            self.response_type = MessageType((flags[0] & 0b10000000) >> 7)
            self.opcode = (flags[0] & 0b01111000) >> 3
            self.is_authoritative_answer = (flags[0] & 0b00000100) >> 2
            self.is_truncated = (flags[0] & 0b00000010) >> 1
            self.is_recursion_desired = (flags[0] & 0b00000001)
            self.is_recursion_available = (flags[1] & 0b10000000) >> 7
            self.return_code = (flags[1] & 0b00001111)
            self.questions, ind = DNSQuestion.from_bytes(
                data, 12, data[4] * 2 ** 8 + data[5])
            self.answers, ind = DNSResourceRecord.from_bytes(
                data, ind, data[6] * 2 ** 8 + data[7])
            self.auth_servers, ind = DNSResourceRecord.from_bytes(
                data, ind, data[8] * 2 ** 8 + data[9])
            self.addit_records, ind = DNSResourceRecord.from_bytes(
                data, ind, data[10] * 2 ** 8 + data[11])
        except IncorrectQuery as e:
            return None
        return self

    def to_bytes(self) -> bytes:
        result = bytearray(self.id)
        result += bytearray([self.response_type << 7 |
                            (self.opcode & 0b1111) << 3 |
                            self.is_authoritative_answer << 2 |
                            self.is_truncated << 1 |
                            self.is_recursion_desired,
                            self.is_recursion_available << 7 |
                            self.return_code,
                            len(self.questions) & (255 << 8),
                            len(self.questions) & 255,
                            len(self.answers) & (255 << 8),
                            len(self.answers) & 255,
                            len(self.auth_servers) & (255 << 8),
                            len(self.auth_servers) & 255,
                            len(self.addit_records) & (255 << 8),
                            len(self.addit_records) & 255])
        for field in [self.questions, self.answers,
                      self.auth_servers, self.addit_records]:
            for record in field:
                result += record.to_bytes(result)
        return bytes(result)


if __name__ == '__main__':
    pass
