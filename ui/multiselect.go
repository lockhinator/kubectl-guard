package ui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// MultiSelectItem represents an item in the multi-select list.
type MultiSelectItem struct {
	Name     string
	Selected bool
}

// defaultViewportHeight is the number of item rows shown before a real terminal
// size is known (bubbletea sends a WindowSizeMsg on start). It keeps a large
// context list from overflowing even if that message never arrives.
const defaultViewportHeight = 10

// chromeRows is how many non-item lines View() draws (header + filter line +
// scroll indicator + help + blanks). The item window is sized to leave room for
// them, so the whole view fits the terminal and nothing is clipped.
const chromeRows = 8

// filterIndices returns the indices of items whose Name contains query
// (case-insensitive substring). An empty/whitespace query matches everything, in
// original order. This is the whole filter logic, kept pure so a large context
// list can be narrowed and tested without a terminal.
func filterIndices(items []MultiSelectItem, query string) []int {
	q := strings.ToLower(strings.TrimSpace(query))
	out := make([]int, 0, len(items))
	for i, it := range items {
		if q == "" || strings.Contains(strings.ToLower(it.Name), q) {
			out = append(out, i)
		}
	}
	return out
}

// viewportOffset returns the scroll offset (index into the visible list of the
// first row to draw) that keeps cursor within a window of height rows. It is the
// standard "scroll just enough to keep the cursor on screen" computation,
// extracted so the math is unit-testable independent of rendering.
//
//	prev is the current offset; cursor is the selected row; total is the number
//	of visible rows; height is how many fit on screen.
func viewportOffset(prev, cursor, total, height int) int {
	if height <= 0 || total <= height {
		return 0 // everything fits (or height unknown): no scroll
	}
	offset := prev
	if cursor < offset {
		offset = cursor // cursor moved above the window: scroll up to it
	} else if cursor >= offset+height {
		offset = cursor - height + 1 // cursor moved below: scroll down to it
	}
	// Never scroll past the end (leaves a partial last page).
	if max := total - height; offset > max {
		offset = max
	}
	if offset < 0 {
		offset = 0
	}
	return offset
}

// nonProductionMarkers name a context that is explicitly NOT production even
// though it contains "prod". Pre-selecting a "non-prod" cluster would be a
// surprising default (the user named it to say it is not prod), so these veto
// the pre-selection.
var nonProductionMarkers = []string{"nonprod", "non-prod", "non_prod"}

// IsProductionContext reports whether name looks like a production context, used
// to pre-select it in the first-run setup wizard. The rule is "contains prod"
// (case-insensitive), matching the ticket's `*prod*` intent, EXCEPT for names
// that carry an explicit non-production marker (`non-prod`, `nonprod`).
//
// This is only a default pre-selection the user reviews and can toggle, and its
// error direction is over-protection (extra confirmation), never a bypass — so a
// rare false positive like "reproduction" is harmless, while the common
// "non-prod" false positive is worth excluding.
func IsProductionContext(name string) bool {
	lc := strings.ToLower(name)
	for _, marker := range nonProductionMarkers {
		if strings.Contains(lc, marker) {
			return false
		}
	}
	return strings.Contains(lc, "prod")
}

// multiSelectModel is the bubbletea model for the scrollable, filterable
// multi-select. cursor and offset index the VISIBLE (filtered) list; items holds
// the full list in stable order so selections survive filtering.
type multiSelectModel struct {
	items     []MultiSelectItem
	visible   []int // indices into items, after the current filter
	cursor    int   // index into visible
	offset    int   // viewport scroll offset, index into visible
	height    int   // item rows on screen
	filtering bool  // true while typing a filter query
	filter    string
	finished  bool
	quitted   bool
}

func newMultiSelectModel(items []MultiSelectItem) multiSelectModel {
	m := multiSelectModel{items: items, height: defaultViewportHeight}
	m.refilter()
	return m
}

// refilter recomputes the visible set from the current filter and re-clamps the
// cursor and viewport so they stay valid as the list shrinks or grows.
func (m *multiSelectModel) refilter() {
	m.visible = filterIndices(m.items, m.filter)
	if m.cursor >= len(m.visible) {
		m.cursor = len(m.visible) - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
	m.offset = viewportOffset(m.offset, m.cursor, len(m.visible), m.height)
}

func (m multiSelectModel) Init() tea.Cmd { return nil }

func (m multiSelectModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		// Reserve rows for the chrome View() draws around the item window: title,
		// blank, the "Select…" line, the filter/blank line, a blank, then the
		// scroll indicator, a blank, and the help line — 8 lines. Under-reserving
		// makes the whole view taller than the terminal; because MultiSelect runs
		// inline (no alt-screen), bubbletea then clips from the TOP, hiding the
		// title. See TestViewFitsTerminalHeight.
		m.height = msg.Height - chromeRows
		if m.height < 1 {
			m.height = 1
		}
		m.offset = viewportOffset(m.offset, m.cursor, len(m.visible), m.height)
		return m, nil
	case tea.KeyMsg:
		if m.filtering {
			return m.updateFiltering(msg)
		}
		return m.updateNavigating(msg)
	}
	return m, nil
}

// updateFiltering handles keys while the user is typing a filter query.
func (m multiSelectModel) updateFiltering(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter":
		m.filtering = false // apply the filter, return to navigation
	case "esc":
		m.filtering = false
		m.filter = "" // discard the filter
		m.refilter()
	case "backspace":
		if m.filter != "" {
			m.filter = m.filter[:len(m.filter)-1]
			m.refilter()
		}
	case "ctrl+c":
		m.quitted = true
		return m, tea.Quit
	default:
		if len(msg.Runes) > 0 {
			m.filter += string(msg.Runes)
			m.refilter()
		}
	}
	return m, nil
}

// updateNavigating handles keys in the normal (non-filter) mode.
func (m multiSelectModel) updateNavigating(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c", "q":
		m.quitted = true
		return m, tea.Quit
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.visible)-1 {
			m.cursor++
		}
	case " ":
		if m.cursor < len(m.visible) {
			idx := m.visible[m.cursor]
			m.items[idx].Selected = !m.items[idx].Selected
		}
	case "/":
		m.filtering = true
	case "enter":
		m.finished = true
		return m, tea.Quit
	case "a":
		// Toggle all currently-visible items: if every visible item is selected,
		// clear them; otherwise select them all.
		allSelected := true
		for _, idx := range m.visible {
			if !m.items[idx].Selected {
				allSelected = false
				break
			}
		}
		for _, idx := range m.visible {
			m.items[idx].Selected = !allSelected
		}
	case "n":
		for i := range m.items {
			m.items[i].Selected = false
		}
		m.finished = true
		return m, tea.Quit
	}
	m.offset = viewportOffset(m.offset, m.cursor, len(m.visible), m.height)
	return m, nil
}

func (m multiSelectModel) View() string {
	if m.finished || m.quitted {
		return ""
	}

	var b strings.Builder
	b.WriteString(titleStyle.Render("kubectl-guard: First-time Setup"))
	b.WriteString("\n\n")
	b.WriteString("Select contexts to protect (space to toggle, enter to confirm):\n")

	// Filter line: shows the query and the match count when active.
	if m.filtering || m.filter != "" {
		fmt.Fprintf(&b, "%s %s (%d match)\n", dimStyle.Render("filter:"), m.filter, len(m.visible))
	} else {
		b.WriteString("\n")
	}
	b.WriteString("\n")

	end := m.offset + m.height
	if end > len(m.visible) {
		end = len(m.visible)
	}
	for row := m.offset; row < end; row++ {
		idx := m.visible[row]
		item := m.items[idx]
		cursor := "  "
		if row == m.cursor {
			cursor = cursorStyle.Render("> ")
		}
		checkbox := "[ ]"
		name := item.Name
		if item.Selected {
			checkbox = selectedStyle.Render("[x]")
			name = selectedStyle.Render(item.Name)
		}
		fmt.Fprintf(&b, "%s%s %s\n", cursor, checkbox, name)
	}

	// Scroll indicator so it is obvious the list continues off-screen.
	if len(m.visible) > m.height {
		fmt.Fprintf(&b, "%s\n", dimStyle.Render(fmt.Sprintf("  (%d-%d of %d)", m.offset+1, end, len(m.visible))))
	}
	if len(m.visible) == 0 {
		b.WriteString(dimStyle.Render("  (no contexts match the filter)\n"))
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.Render("[/] filter  [space] toggle  [a] toggle visible  [n] none  [enter] confirm  [q] quit"))
	b.WriteString("\n")

	return b.String()
}

// MultiSelect presents an interactive multi-select prompt.
// Returns the selected items and whether the user confirmed (vs quit).
func MultiSelect(items []MultiSelectItem) ([]MultiSelectItem, bool) {
	p := tea.NewProgram(newMultiSelectModel(items))
	finalModel, err := p.Run()
	if err != nil {
		return nil, false
	}
	result := finalModel.(multiSelectModel)
	if result.quitted {
		return nil, false
	}
	return result.items, true
}
