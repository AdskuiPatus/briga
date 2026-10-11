import sys
from pathlib import Path

# корень проекта — в sys.path, чтобы `import madrigal` работал из тестов
sys.path.insert(0, str(Path(__file__).parent))
