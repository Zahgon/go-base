package cmd

import (
	"fmt"
	"log"
	"os"
	"reflect"
	"runtime"
	"sort"
	"strings"

	"github.com/dhax/go-base/api"
	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
)

var (
	routes bool
)

// gendocCmd represents the gendoc command
var gendocCmd = &cobra.Command{
	Use:   "gendoc",
	Short: "Generate project documentation",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		if routes {
			genRoutesDoc()
		}
	},
}

func init() {
	RootCmd.AddCommand(gendocCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// gendocCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// gendocCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	gendocCmd.Flags().BoolVarP(&routes, "routes", "r", false, "create api routes markdown file")
}

const projectPath = "github.com/dhax/go-base"

func genRoutesDoc() {
	api, _ := api.New(false)
	fmt.Print("generating routes markdown file: ")
	md := markdownRoutesDoc(api, projectPath, "GoBase REST API.")
	if err := os.WriteFile("routes.md", []byte(md), 0644); err != nil {
		log.Println(err)
		return
	}
	fmt.Println("OK")
}

// markdownRoutesDoc renders the routes registered on the engine as a markdown document.
func markdownRoutesDoc(engine *gin.Engine, projectPath, intro string) string {
	routes := engine.Routes()
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Path != routes[j].Path {
			return routes[i].Path < routes[j].Path
		}
		return routes[i].Method < routes[j].Method
	})

	var buf strings.Builder
	fmt.Fprintf(&buf, "# %s\n\n%s\n\n## Routes\n\n", projectPath, intro)

	for _, route := range routes {
		fmt.Fprintf(&buf, "<details>\n<summary>`%s`</summary>\n\n", route.Path)
		fmt.Fprintf(&buf, "- **%s**\n", route.Path)
		fmt.Fprintf(&buf, "\t- _%s_\n", route.Method)
		fmt.Fprintf(&buf, "\t\t- [%s](%s)\n", handlerName(route.Handler), handlerSource(route.HandlerFunc))
		buf.WriteString("\n</details>\n")
	}

	fmt.Fprintf(&buf, "\nTotal # of routes: %d\n", len(routes))

	return buf.String()
}

// handlerName strips the project path from a fully qualified handler symbol.
func handlerName(handler string) string {
	return strings.TrimPrefix(handler, projectPath+"/")
}

// handlerSource returns the project relative file and line a handler is defined at.
func handlerSource(handler gin.HandlerFunc) string {
	pc := reflect.ValueOf(handler).Pointer()
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return ""
	}
	file, line := fn.FileLine(pc)
	if idx := strings.LastIndex(file, projectPath); idx >= 0 {
		file = file[idx+len(projectPath):]
	}
	return fmt.Sprintf("%s#L%d", file, line)
}
