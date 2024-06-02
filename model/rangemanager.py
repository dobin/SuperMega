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


    def print_all(self):
        logger.info("Min: {}  Max: {}".format(self.min, self.max))
        for i in self.intervals:
            logger.info("Interval: {}-{}".format(i.begin, i.end))


    def add_range(self, start, end):
        if start < self.min or end > self.max:
            raise ValueError("Ranges must be within 0x{:X} - 0x{:X}, not: 0x{:X}-0x{:X}".format(
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

        # at the end
        if last_end < self.max:
            return last_end, self.max-1
        
        return None
    
    
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
    

    def find_largest_gap(self):
        # First, sort intervals by the starting point
        sorted_intervals = sorted(self.intervals, key=lambda x: x.begin)
        
        # Initial largest gap is 0
        largest_gap = 0
        
        # Start by considering the gap from min to the first interval's start, if there are any intervals
        if sorted_intervals:
            largest_gap = sorted_intervals[0].begin - self.min
        
        # Iterate over the intervals and find the gap between consecutive intervals
        last_end = sorted_intervals[0].end if sorted_intervals else self.min
        for interval in sorted_intervals[1:]:
            # Calculate the gap between the current interval's start and the last interval's end
            current_gap = interval.begin - last_end
            if current_gap > largest_gap:
                largest_gap = current_gap
            last_end = max(last_end, interval.end)  # Update last_end considering overlapping intervals
        
        # Finally consider the gap from the last interval's end to max
        if sorted_intervals:
            final_gap = self.max - sorted_intervals[-1].end
            if final_gap > largest_gap:
                largest_gap = final_gap
        
        return largest_gap