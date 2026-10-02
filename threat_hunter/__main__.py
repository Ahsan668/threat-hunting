import click

@click.group()
def main():
    """threat-hunter: Automated threat hunting platform"""
    pass

@main.command()
def test():
    """Test if threat-hunter is working"""
    click.echo("✓ threat-hunter CLI is working!")

if __name__ == '__main__':
    main()
