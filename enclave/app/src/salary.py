from collections import OrderedDict
import uuid
from typing import Optional, Dict

class PositionAndTotal:
    def __init__(self, position: int, total: int):
        self.position = position
        self.total = total
    
    def to_dict(self) -> Dict[str, int]:
        return {
            "position": self.position,
            "total": self.total
        }

class Salary:
    def __init__(self):
        """Constructor"""
        self.salary_map: OrderedDict[str, int] = OrderedDict()

    def add(self, salary: int) -> str:
        """Add a salary entry and return its UUID"""
        id_str = str(uuid.uuid4())
        self.salary_map[id_str] = salary
        self._sort_salary_map()
        return id_str

    def _sort_salary_map(self):
        """Sort salary map by salary value in descending order"""
        # Sort by value (salary) in descending order
        sorted_items = sorted(self.salary_map.items(), key=lambda x: x[1], reverse=True)
        self.salary_map = OrderedDict(sorted_items)

    def get_position_and_total(self, id_str: str) -> Optional[Dict[str, int]]:
        """Get position and total count for a given ID"""
        if id_str not in self.salary_map:
            return None
        
        # Find the position (1-indexed)
        position = list(self.salary_map.keys()).index(id_str) + 1
        total = len(self.salary_map)
        
        position_and_total = PositionAndTotal(position, total)
        return position_and_total.to_dict()

    def clear(self):
        """Clear all salary entries"""
        self.salary_map.clear()