package ui

import (
	"reflect"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func items(names ...string) []MultiSelectItem {
	out := make([]MultiSelectItem, len(names))
	for i, n := range names {
		out[i] = MultiSelectItem{Name: n}
	}
	return out
}

func TestFilterIndices(t *testing.T) {
	list := items("prod-us", "prod-eu", "staging", "dev", "PRODUCTION")
	tests := []struct {
		query string
		want  []int
	}{
		{"", []int{0, 1, 2, 3, 4}},
		{"   ", []int{0, 1, 2, 3, 4}},
		{"prod", []int{0, 1, 4}}, // case-insensitive; PRODUCTION matches
		{"PROD", []int{0, 1, 4}},
		{"staging", []int{2}},
		{"-eu", []int{1}},
		{"nomatch", []int{}},
	}
	for _, tt := range tests {
		if got := filterIndices(list, tt.query); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("filterIndices(%q) = %v, want %v", tt.query, got, tt.want)
		}
	}
}

func TestViewportOffset(t *testing.T) {
	tests := []struct {
		name                        string
		prev, cursor, total, height int
		want                        int
	}{
		{"everything fits", 0, 3, 5, 10, 0},
		{"height unknown", 0, 50, 100, 0, 0},
		{"cursor within window", 2, 4, 100, 10, 2},
		{"cursor below window scrolls down", 0, 12, 100, 10, 3}, // 12-10+1
		{"cursor above window scrolls up", 20, 5, 100, 10, 5},
		{"cursor at last row", 0, 99, 100, 10, 90}, // clamped to total-height
		{"offset never past end", 95, 99, 100, 10, 90},
		{"cursor at top", 5, 0, 100, 10, 0},
		{"exactly filling", 0, 9, 10, 10, 0}, // total==height -> no scroll
		{"one past window bottom", 0, 10, 20, 10, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := viewportOffset(tt.prev, tt.cursor, tt.total, tt.height); got != tt.want {
				t.Errorf("viewportOffset(prev=%d cursor=%d total=%d height=%d) = %d, want %d",
					tt.prev, tt.cursor, tt.total, tt.height, got, tt.want)
			}
		})
	}
}

// TestViewportKeepsCursorVisible is a property check: after computing the offset,
// the cursor is always within [offset, offset+height).
func TestViewportKeepsCursorVisible(t *testing.T) {
	const total, height = 500, 20
	offset := 0
	for cursor := 0; cursor < total; cursor++ { // walk down
		offset = viewportOffset(offset, cursor, total, height)
		if cursor < offset || cursor >= offset+height {
			t.Fatalf("cursor %d not visible in window [%d,%d)", cursor, offset, offset+height)
		}
	}
	for cursor := total - 1; cursor >= 0; cursor-- { // walk back up
		offset = viewportOffset(offset, cursor, total, height)
		if cursor < offset || cursor >= offset+height {
			t.Fatalf("cursor %d not visible in window [%d,%d)", cursor, offset, offset+height)
		}
	}
}

func TestIsProductionContext(t *testing.T) {
	yes := []string{"prod", "prod-us-east-1", "us-prod", "PRODUCTION", "my-production-cluster", "arn:aws:eks:us-east-1:1:cluster/prod-main"}
	// Explicit non-production names must NOT be pre-selected even though they
	// contain "prod".
	no := []string{"dev", "staging", "test", "qa", "sandbox", "local", "non-prod", "nonprod", "NON-PROD", "staging-nonprod", "non_prod"}
	for _, n := range yes {
		if !IsProductionContext(n) {
			t.Errorf("IsProductionContext(%q) = false, want true", n)
		}
	}
	for _, n := range no {
		if IsProductionContext(n) {
			t.Errorf("IsProductionContext(%q) = true, want false", n)
		}
	}
}

// --- model behavior via Update ---

func key(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "backspace":
		return tea.KeyMsg{Type: tea.KeyBackspace}
	case "space":
		return tea.KeyMsg{Type: tea.KeySpace}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "/":
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
	}
}

func send(m multiSelectModel, msgs ...tea.Msg) multiSelectModel {
	var model tea.Model = m
	for _, msg := range msgs {
		model, _ = model.Update(msg)
	}
	return model.(multiSelectModel)
}

func TestModelScrollsWithCursor(t *testing.T) {
	names := make([]string, 500)
	for i := range names {
		names[i] = "ctx-" + string(rune('a'+i%26)) + "-" + itoa(i)
	}
	m := newMultiSelectModel(items(names...))
	m = send(m, tea.WindowSizeMsg{Width: 80, Height: 20}) // height 13 rows

	// Walk the cursor to the bottom; the viewport must follow.
	for i := 0; i < 499; i++ {
		m = send(m, key("down"))
	}
	if m.cursor != 499 {
		t.Fatalf("cursor = %d, want 499", m.cursor)
	}
	if m.cursor < m.offset || m.cursor >= m.offset+m.height {
		t.Errorf("cursor %d not in window [%d,%d)", m.cursor, m.offset, m.offset+m.height)
	}
	// The rendered view must not contain all 500 items (proving it's windowed).
	view := m.View()
	if lines := countLines(view); lines > 30 {
		t.Errorf("view rendered %d lines; a 500-item list must be windowed", lines)
	}
}

// TestViewFitsTerminalHeight pins the chrome-row reservation (F1): the rendered
// view must not be taller than the terminal, or bubbletea's inline renderer
// clips lines from the TOP (hiding the title). For a list longer than the
// window, at various terminal heights, the view's line count must be <= height.
func TestViewFitsTerminalHeight(t *testing.T) {
	names := make([]string, 500)
	for i := range names {
		names[i] = "ctx-" + itoa(i)
	}
	for _, h := range []int{10, 12, 20, 24, 40, 50} {
		m := newMultiSelectModel(items(names...))
		mm := send(m, tea.WindowSizeMsg{Width: 80, Height: h})
		// Scroll into the middle so the scroll indicator (an extra chrome line) is
		// present — the worst case for height.
		for i := 0; i < 250; i++ {
			mm = send(mm, key("down"))
		}
		if lines := countLines(mm.View()); lines > h {
			t.Errorf("terminal height %d: view is %d lines (must be <= %d, or the top is clipped)", h, lines, h)
		}
	}
}

func TestModelFilterNarrowsList(t *testing.T) {
	m := newMultiSelectModel(items("prod-us", "prod-eu", "staging-1", "dev"))
	if len(m.visible) != 4 {
		t.Fatalf("initial visible = %d, want 4", len(m.visible))
	}
	m = send(m, key("/"), key("prod"))
	if !m.filtering {
		t.Error("should be in filtering mode after '/'")
	}
	if len(m.visible) != 2 {
		t.Errorf("visible after filter 'prod' = %d, want 2", len(m.visible))
	}
	// Enter applies the filter and returns to navigation.
	m = send(m, key("enter"))
	if m.filtering {
		t.Error("enter should exit filtering mode")
	}
	if len(m.visible) != 2 {
		t.Errorf("filter should persist after enter; visible = %d", len(m.visible))
	}
	// Esc-based clear restores the full list. (Re-enter filter first.)
	m = send(m, key("/"), key("x"))
	if len(m.visible) != 0 {
		t.Errorf("filter 'x' should match nothing; visible = %d", len(m.visible))
	}
	m = send(m, key("esc"))
	if m.filtering || m.filter != "" || len(m.visible) != 4 {
		t.Errorf("esc should clear the filter: filtering=%v filter=%q visible=%d", m.filtering, m.filter, len(m.visible))
	}
}

// TestModelSelectionSurvivesFilter: toggling an item, then filtering it out and
// back, must preserve its selected state (selection is on the full list).
func TestModelSelectionSurvivesFilter(t *testing.T) {
	m := newMultiSelectModel(items("prod-us", "prod-eu", "staging"))
	// cursor at 0 (prod-us); select it.
	m = send(m, key("space"))
	if !m.items[0].Selected {
		t.Fatal("prod-us should be selected")
	}
	// Filter to "staging" (hides prod-us), then clear.
	m = send(m, key("/"), key("staging"), key("enter"))
	m = send(m, key("/"), key("esc"))
	if !m.items[0].Selected {
		t.Error("prod-us selection must survive filtering it out and back")
	}
}

// TestModelToggleVisibleOnly: 'a' toggles only the currently-visible (filtered)
// items, leaving filtered-out items untouched.
func TestModelToggleVisibleOnly(t *testing.T) {
	m := newMultiSelectModel(items("prod-us", "prod-eu", "staging"))
	m = send(m, key("/"), key("prod"), key("enter")) // visible = prod-us, prod-eu
	m = send(m, key("a"))                            // select all visible
	if !m.items[0].Selected || !m.items[1].Selected {
		t.Error("'a' should select both visible prod items")
	}
	if m.items[2].Selected {
		t.Error("'a' must not touch the filtered-out staging item")
	}
}

func TestModelFilterRuneNotTreatedAsCommand(t *testing.T) {
	// While filtering, typing 'q' must go into the query, NOT quit.
	m := newMultiSelectModel(items("qa-1", "prod"))
	m = send(m, key("/"), key("q"))
	if m.quitted {
		t.Error("'q' while filtering must not quit")
	}
	if m.filter != "q" || len(m.visible) != 1 {
		t.Errorf("filter=%q visible=%d, want filter 'q' matching qa-1", m.filter, len(m.visible))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func countLines(s string) int {
	n := 0
	for _, r := range s {
		if r == '\n' {
			n++
		}
	}
	return n
}
