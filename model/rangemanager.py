import logging
from intervaltree import Interval, IntervalTree


logger = logging.getLogger("RangeManager")


class RangeManager:
    def __init__(self, min=0, max=1000):
        self.intervals = IntervalTree()
        self.min = min
        self.max = max


    def merge_overlaps(self):
        self.intervals.merge_overlaps(strict=False)


    def add_range(self, start, end):
        if start < self.min or end > self.max:
            raise ValueError("Ranges must be within 0x{:X} and 0x{:X}, not 0x{:X}/0x{:X}".format(
                self.min, self.max, start, end
            ))
        self.intervals.add(Interval(start, end))


    def find_hole(self, hole_size):
        sorted_intervals = sorted(self.intervals)
        last_end = self.min
        for interval in sorted_intervals:
            start, end = interval.begin, interval.end
            if start - last_end >= hole_size:
                return (last_end + 1, start - 1)
            last_end = max(last_end, end)
    
    
    def find_holes(self, hole_size):
        sorted_intervals = sorted(self.intervals)
        holes = []
        last_end = self.min
        for interval in sorted_intervals:
            start, end = interval.begin, interval.end
            if start - last_end >= hole_size:
                holes.append((last_end + 1, start - 1))
            last_end = max(last_end, end)
        if last_end < self.max and self.max - last_end >= hole_size:
            holes.append((last_end + 1, self.max))
        return holes