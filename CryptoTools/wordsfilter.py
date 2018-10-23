import sys
import click
import unidecode


@click.command()
@click.argument('input_file_path')
@click.argument('output_file_path')
def main(input_file_path, output_file_path):
    words = set()

    with open(input_file_path) as in_file:

        for line in in_file.readlines():
            word = line.strip().lower()

            sep_index = line.find('/')
            if sep_index >= 0:
                word = word[:sep_index]
            words.add(unidecode.unidecode(word))

    with open(output_file_path, 'w') as out_file:
        for word in words:
            out_file.write(word + '\n')

    return 0


if __name__ == '__main__':
    sys.exit(main())
