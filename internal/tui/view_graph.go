package tui

import (
	"fmt"
	"strings"

	"github.com/saptreekly/casre/internal/output"
	"github.com/saptreekly/casre/internal/scanner"
)

func (m model) viewGraph() string {
	r := m.result()
	items := graphItems(r)
	if len(items) == 0 {
		return styleMuted.Render("No hop graph for this target.")
	}

	idx := clamp(m.hopIdx, 0, len(items)-1)
	w := max(40, m.vp.Width)

	var b strings.Builder
	b.WriteString(pageChrome("Redirect chain", len(items), "↑↓ move  ·  enter full URL  ·  c copy", w))

	for i, it := range items {
		last := i == len(items)-1
		selected := i == idx
		status := statusStr(it.status)
		host := it.host
		if host == "" {
			host = "—"
		}
		meta := viaRole(it.via, it.role)

		branch := "├─"
		if last {
			branch = "└─"
		}

		label := host
		if meta != "" {
			label = host + "  ·  " + meta
		}

		plain := fmt.Sprintf("%s%s %-4s  %s", gutter(selected), branch, status, label)
		b.WriteString(selectRow(selected, plain, w) + "\n")

		if !last {
			via := ""
			if i+1 < len(items) {
				via = items[i+1].via
			}
			if via == "" {
				via = it.via
			}
			if via == "" {
				via = "followed"
			}
			railStyle := styleMuted
			if selected {
				railStyle = styleDot
			}
			b.WriteString(railStyle.Render(fit("  │     "+via, w)) + "\n")
		}
	}

	b.WriteString("\n")
	b.WriteString(m.hopDetailCard(items[idx], w))
	return b.String()
}

type hopItem struct {
	url    string
	host   string
	status int
	role   string
	via    string
	server string
	final  string
	depth  int
}

func graphItems(r scanner.Result) []hopItem {
	viaByURL := map[string]string{}
	nodeByURL := map[string]scanner.GraphNode{}
	if r.Graph != nil {
		idURL := map[string]string{}
		for _, n := range r.Graph.Nodes {
			idURL[n.ID] = n.URL
			nodeByURL[n.URL] = n
		}
		for _, e := range r.Graph.Edges {
			if to, ok := idURL[e.To]; ok {
				viaByURL[to] = e.Via
			}
		}
	}

	if len(r.Hops) > 0 {
		out := make([]hopItem, 0, len(r.Hops))
		for _, h := range r.Hops {
			it := hopItem{
				url:   h.URL,
				host:  h.Host,
				role:  h.Role,
				depth: h.Depth,
				via:   viaByURL[h.URL],
			}
			if h.Probe != nil {
				it.status = h.Probe.StatusCode
				it.server = h.Probe.Server
				if h.Probe.FinalURL != "" && h.Probe.FinalURL != h.Probe.URL {
					it.final = h.Probe.FinalURL
				}
			}
			if n, ok := nodeByURL[h.URL]; ok {
				if it.status == 0 {
					it.status = n.StatusCode
				}
				if it.role == "" {
					it.role = n.Role
				}
			}
			out = append(out, it)
		}
		return out
	}

	if r.Graph == nil {
		return nil
	}
	out := make([]hopItem, 0, len(r.Graph.Nodes))
	for _, n := range r.Graph.Nodes {
		out = append(out, hopItem{
			url:    n.URL,
			host:   n.Host,
			status: n.StatusCode,
			role:   n.Role,
			via:    viaByURL[n.URL],
			depth:  n.Depth,
		})
	}
	return out
}

func (m model) hopDetailCard(it hopItem, w int) string {
	innerW := max(28, w-4)
	var b strings.Builder
	b.WriteString(styleSection.Render("This hop") + "\n\n")
	b.WriteString(kv("Host", fit(it.host, max(12, innerW-12))) + "\n")
	b.WriteString(kv("Status", statusStr(it.status)) + "\n")
	if it.role != "" {
		b.WriteString(kv("Role", it.role) + "\n")
	}
	if it.via != "" {
		b.WriteString(kv("How", it.via) + "\n")
	}
	if it.server != "" {
		b.WriteString(kv("Server", fit(it.server, max(12, innerW-12))) + "\n")
	}
	b.WriteString("\n")
	u := output.CompactURL(it.url)
	if m.showFull {
		u = it.url
	}
	b.WriteString(styleMuted.Render("URL") + "\n")
	b.WriteString(wrap(u, innerW) + "\n")
	if it.final != "" {
		fu := output.CompactURL(it.final)
		if m.showFull {
			fu = it.final
		}
		b.WriteString("\n" + styleMuted.Render("Final") + "\n")
		b.WriteString(wrap(fu, innerW) + "\n")
	}
	b.WriteString("\n" + styleMuted.Render("f full url  ·  c copy"))

	// Border sits outside Width — Size box to w columns total.
	boxW := max(20, w-2)
	return styleFrame.
		Width(boxW).
		BorderForeground(colAccent).
		Render(b.String())
}

func statusStr(code int) string {
	if code <= 0 {
		return "——"
	}
	return fmt.Sprintf("%d", code)
}

func viaRole(via, role string) string {
	parts := []string{}
	if via != "" {
		parts = append(parts, via)
	}
	if role != "" && role != "—" {
		parts = append(parts, role)
	}
	return strings.Join(parts, " · ")
}
