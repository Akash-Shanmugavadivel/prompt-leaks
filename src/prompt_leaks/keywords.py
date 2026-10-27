"""Small Aho-Corasick keyword prefilter implemented with the standard library."""

from __future__ import annotations

from collections import deque


class KeywordIndex:
    """Map keyword occurrences to the rules that need full regex evaluation."""

    def __init__(self) -> None:
        self._next: list[dict[str, int]] = [{}]
        self._fail: list[int] = [0]
        self._outputs: list[set[str]] = [set()]

    def add(self, keyword: str, rule_id: str) -> None:
        state = 0
        for char in keyword.casefold():
            next_state = self._next[state].get(char)
            if next_state is None:
                next_state = len(self._next)
                self._next[state][char] = next_state
                self._next.append({})
                self._fail.append(0)
                self._outputs.append(set())
            state = next_state
        self._outputs[state].add(rule_id)

    def build(self) -> None:
        queue: deque[int] = deque()
        for state in self._next[0].values():
            queue.append(state)
            self._fail[state] = 0

        while queue:
            state = queue.popleft()
            for char, child in self._next[state].items():
                queue.append(child)
                fallback = self._fail[state]
                while fallback and char not in self._next[fallback]:
                    fallback = self._fail[fallback]
                self._fail[child] = self._next[fallback].get(char, 0)
                self._outputs[child].update(self._outputs[self._fail[child]])

    def matching_rules(self, text: str) -> set[str]:
        matched: set[str] = set()
        state = 0
        for char in text.casefold():
            while state and char not in self._next[state]:
                state = self._fail[state]
            state = self._next[state].get(char, 0)
            matched.update(self._outputs[state])
        return matched

