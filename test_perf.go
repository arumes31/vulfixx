package main

import (
	"fmt"
)

func main() {
	teams := []map[string]interface{}{}
	teams = append(teams, map[string]interface{}{"ID": 1, "Name": "Team A"})
	teams = append(teams, map[string]interface{}{"ID": 2, "Name": "Team B"})

	var data map[string]interface{}
	data = make(map[string]interface{})
	data["UserTeams"] = teams

	activeTeamID := 2
	var teamName string
	var found bool

	if teamsVal, exists := data["UserTeams"]; exists {
		if teamsList, ok := teamsVal.([]map[string]interface{}); ok {
			for _, t := range teamsList {
				if id, ok := t["ID"].(int); ok && id == activeTeamID {
					if name, ok := t["Name"].(string); ok {
						teamName = name
						found = true
						break
					}
				}
			}
		} else {
			fmt.Println("Type assertion failed")
		}
	}

	if found {
		fmt.Println("Found:", teamName)
	} else {
		fmt.Println("Not found")
	}
}
