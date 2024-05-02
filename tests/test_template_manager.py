import pytest
from app.utils.template_manager import TemplateManager
from unittest.mock import mock_open, patch

# Fixture to create an instance of TemplateManager
@pytest.fixture
def template_manager():
    return TemplateManager()

# Test reading templates
def test_read_template(template_manager):
    # Mock the open function within the context of _read_template method
    mock_file_content = "Hello, {name}!"
    with patch("builtins.open", mock_open(read_data=mock_file_content)) as mocked_file:
        result = template_manager._read_template("greeting.md")
        mocked_file.assert_called_once_with(template_manager.templates_dir / "greeting.md", 'r', encoding='utf-8')
        assert result == mock_file_content

# Test applying email styles
def test_apply_email_styles(template_manager):
    html_content = "<h1>Hello</h1><p>Welcome</p>"
    expected_result = """<div style="font-family: Arial, sans-serif; font-size: 16px; color: #333333; background-color: #ffffff; line-height: 1.5;"><h1 style="font-size: 24px; color: #333333; font-weight: bold; margin-top: 20px; margin-bottom: 10px;">Hello</h1><p style="font-size: 16px; color: #666666; margin: 10px 0; line-height: 1.6;">Welcome</p></div>"""
    styled_html = template_manager._apply_email_styles(html_content)
    assert styled_html == expected_result

# Test rendering templates with context
def test_render_template(template_manager):
    # Mock _read_template to return specific markdown for headers, footers, and main template
    header = "Header Content\n"
    main_template = "Main Content with {name}\n"
    footer = "Footer Content\n"

    # Mock _read_template to return the pre-formatted main template with context applied
    with patch.object(template_manager, '_read_template') as mock_read_template:
        mock_read_template.side_effect = [
            header,  # Return for header template read
            main_template.format(name='John Doe'),  # Return for main template read
            footer  # Return for footer template read
        ]

        context = {'name': 'John Doe'}
        result = template_manager.render_template("main", **context)
        # Check if the rendered content includes the styled version of the markdown
        assert "John Doe" in result
        assert "<div style=" in result  # Simplistic check for styling application
