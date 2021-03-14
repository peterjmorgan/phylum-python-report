import sys
from rich.console import Console
from rich.table import Table
from rich.layout import Layout


def main(argc,argv):
    layout = Layout()
    console = Console()

    table = Table(show_header=True, header_style="Bold Magenta")
    table.add_column("Package Name", width=20)
    table.add_column("High")
    table.add_column("Med")
    table.add_column("Low")

    table.add_row('react-is','1','0','3')
    table.add_row('yargs','3','1','0')
    table.add_row('yauzl','1','3','2')


    layout.split(Layout(name='upper'),Layout(name='lower'))
    layout['lower'].size = 10
    layout['upper'].split(Layout(name='left'),Layout(name='right'),direction='horizontal')
    layout['right'].update(table)
    console.print(layout)

if __name__ == "__main__":
    main(len(sys.argv),sys.argv)
