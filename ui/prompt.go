// Package ui provides interactive terminal prompts for kubectl-guard.
package ui

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("12"))

	selectedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("10"))

	cursorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("14"))

	warningStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("11"))

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("10"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("8"))
)

// Confirm prompts the user for a yes/no confirmation.
// Returns true if the user confirms, false otherwise.
func Confirm(message string) bool {
	fmt.Print(warningStyle.Render("⚠️  "+message) + "\n")
	fmt.Print("Confirm? [y/N]: ")

	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	response = strings.ToLower(strings.TrimSpace(response))
	return response == "y" || response == "yes"
}

// MultiSelectItem represents an item in the multi-select list.
type MultiSelectItem struct {
	Name     string
	Selected bool
}

// multiSelectModel is the bubbletea model for multi-select.
type multiSelectModel struct {
	items    []MultiSelectItem
	cursor   int
	finished bool
	quitted  bool
}

func (m multiSelectModel) Init() tea.Cmd {
	return nil
}

func (m multiSelectModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			m.quitted = true
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.items)-1 {
				m.cursor++
			}
		case " ":
			m.items[m.cursor].Selected = !m.items[m.cursor].Selected
		case "enter":
			m.finished = true
			return m, tea.Quit
		case "a":
			// Toggle all
			allSelected := true
			for _, item := range m.items {
				if !item.Selected {
					allSelected = false
					break
				}
			}
			for i := range m.items {
				m.items[i].Selected = !allSelected
			}
		case "n":
			// Select none
			for i := range m.items {
				m.items[i].Selected = false
			}
			m.finished = true
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m multiSelectModel) View() string {
	if m.finished || m.quitted {
		return ""
	}

	var b strings.Builder

	b.WriteString(titleStyle.Render("kubectl-guard: First-time Setup"))
	b.WriteString("\n\n")
	b.WriteString("Select contexts to protect (space to toggle, enter to confirm):\n\n")

	for i, item := range m.items {
		cursor := "  "
		if i == m.cursor {
			cursor = cursorStyle.Render("> ")
		}

		checkbox := "[ ]"
		name := item.Name
		if item.Selected {
			checkbox = selectedStyle.Render("[x]")
			name = selectedStyle.Render(item.Name)
		}

		b.WriteString(fmt.Sprintf("%s%s %s\n", cursor, checkbox, name))
	}

	b.WriteString("\n")
	b.WriteString(dimStyle.Render("[n] None - don't protect any contexts"))
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("[a] Toggle all"))
	b.WriteString("\n")

	return b.String()
}

// MultiSelect presents an interactive multi-select prompt.
// Returns the selected items and whether the user confirmed (vs quit).
func MultiSelect(items []MultiSelectItem) ([]MultiSelectItem, bool) {
	m := multiSelectModel{
		items: items,
	}

	p := tea.NewProgram(m)
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

// PrintSuccess prints a success message.
func PrintSuccess(message string) {
	fmt.Println(successStyle.Render("✓ " + message))
}

// PrintWarning prints a warning message.
func PrintWarning(message string) {
	fmt.Println(warningStyle.Render("⚠️  " + message))
}

// PrintInfo prints an info message.
func PrintInfo(message string) {
	fmt.Println(message)
}
