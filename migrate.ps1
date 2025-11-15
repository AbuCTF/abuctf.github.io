# migrate.ps1 - Convert Markdown images to Hugo figure shortcodes
# Usage: .\migrate.ps1 <path-to-index.md>

param(
    [Parameter(Mandatory=$true)]
    [string]$FilePath
)

# Check if file exists
if (-not (Test-Path $FilePath)) {
    Write-Host "Error: File '$FilePath' not found." -ForegroundColor Red
    exit 1
}

# Read the file content
$content = Get-Content $FilePath -Raw -Encoding UTF8

# Check if file already uses Hugo figure shortcodes
$hugoFigurePattern = '\{\{<\s*figure\s+src='
$existingHugoFigures = [regex]::Matches($content, $hugoFigurePattern).Count

# Check for Markdown images
$markdownImagePattern = '!\[([^\]]*)\]\(([^)]+)\)'
$markdownImages = [regex]::Matches($content, $markdownImagePattern).Count

Write-Host "`nAnalyzing file..." -ForegroundColor Cyan
Write-Host "  - Found $existingHugoFigures Hugo figure shortcode(s)" -ForegroundColor Gray
Write-Host "  - Found $markdownImages Markdown image(s)" -ForegroundColor Gray

# If no Markdown images found, exit early
if ($markdownImages -eq 0) {
    Write-Host "`nNo Markdown images to convert. File appears to be already migrated or contains no images." -ForegroundColor Yellow
    exit 0
}

# Backup the original file
$backupPath = "$FilePath.backup"
Copy-Item $FilePath $backupPath -Force
Write-Host "`nCreated backup at: $backupPath" -ForegroundColor Green

# Counter for replacements
$replacementCount = 0

# Regex pattern to match: ![alt text](image.png)
# Captures: alt text and image path
# This pattern avoids matching if it's inside code blocks or already part of Hugo shortcode
$pattern = '(?<!`)!\[([^\]]*)\]\(([^)]+)\)(?!`)'

# Replace function
$newContent = [regex]::Replace($content, $pattern, {
    param($match)
    
    $fullMatch = $match.Value
    $altText = $match.Groups[1].Value
    $imagePath = $match.Groups[2].Value
    
    # Skip if this looks like it's part of an existing Hugo shortcode context
    $contextStart = [Math]::Max(0, $match.Index - 50)
    $contextLength = [Math]::Min(100, $content.Length - $contextStart)
    $context = $content.Substring($contextStart, $contextLength)
    
    if ($context -match '\{\{<.*figure.*>\}\}') {
        Write-Host "  Skipping (already in Hugo context): $fullMatch" -ForegroundColor DarkGray
        return $fullMatch
    }
    
    # URL decode the image path (e.g., image%201.png -> image 1.png)
    $imagePath = [System.Uri]::UnescapeDataString($imagePath)
    
    # If alt text is empty or generic, use filename without extension
    if ([string]::IsNullOrWhiteSpace($altText) -or $altText -eq "image.png") {
        $altText = [System.IO.Path]::GetFileNameWithoutExtension($imagePath)
    }
    
    $script:replacementCount++
    
    # Return Hugo figure shortcode
    return "{{< figure src=`"$imagePath`" alt=`"$altText`" >}}"
})

# Only write if changes were made
if ($replacementCount -gt 0) {
    Set-Content -Path $FilePath -Value $newContent -Encoding UTF8 -NoNewline
    
    Write-Host "`nMigration complete!" -ForegroundColor Green
    Write-Host "Replaced $replacementCount Markdown image(s) with Hugo figure shortcodes." -ForegroundColor Cyan
    Write-Host "`nOriginal file backed up to: $backupPath" -ForegroundColor Yellow
    Write-Host "Modified file: $FilePath" -ForegroundColor Yellow
} else {
    # Remove backup if no changes were made
    Remove-Item $backupPath -Force
    Write-Host "`nNo changes made - all images already in Hugo format or skipped." -ForegroundColor Yellow
}
