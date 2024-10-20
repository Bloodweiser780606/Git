# Import necessary modules
Add-Type -AssemblyName System.Windows.Forms

# Create a new form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Script Selector"
$form.Size = New-Object System.Drawing.Size(300, 200)

# Create a label and textbox for the folder path
$label = New-Object System.Windows.Forms.Label
$label.Text = "Folder Path:"
$label.Location = New-Object System.Drawing.Point(10, 10)
$label.AutoSize = $true
$form.Controls.Add($label)

$folderTextBox = New-Object System.Windows.Forms.TextBox
$folderTextBox.Location = New-Object System.Drawing.Point(10, 30)
$folderTextBox.Size = New-Object System.Drawing.Size(200, 20)
$form.Controls.Add($folderTextBox)

# Create a button to browse for the folder
$browseButton = New-Object System.Windows.Forms.Button
$browseButton.Text = "Browse"
$browseButton.Location = New-Object System.Drawing.Point(220, 30)
$browsebutton.rootfolder = "mycomputer"
$browseButton.Size = New-Object System.Drawing.Size(70, 20)
$browseButton.Add_Click 
    $folderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
    if ($folderDialog.ShowDialog){ -eq (System.Windows.Forms.DialogResult.OK)} {
        ($folderTextBox.Text()) = $folderDialog.SelectedPath
    }

$form.Controls.Add($browseButton)

# Create a dropdown list to display the scripts
$scriptComboBox = New-Object System.Windows.Forms.ComboBox
$scriptComboBox.Location = New-Object System.Drawing.Point(10, 60)
$scriptComboBox.Size = New-Object System.Drawing.Size(280, 20)
$form.Controls.Add($scriptComboBox)

# Create a button to execute the selected script
$executeButton = New-Object System.Windows.Forms.Button
$executeButton.Text = "Execute"
$executeButton.Location = New-Object System.Drawing.Point(10, 90)
$executeButton.Size = New-Object System.Drawing.Size(280, 20)
$executeButton.Add_Click({
    if ($scriptComboBox.SelectedItem) {
        $scriptPath = Join-Path $folderTextBox.Text ($scriptComboBox.SelectedItem)
        Invoke-Command -FilePath $scriptPath
    } else {
        [System.Windows.Forms.MessageBox]::Show("Please select a script.")
    }
})
$form.Controls.Add($executeButton)

# Populate the dropdown list with scripts from the selected folder
function PopulateScriptList {
    param([string]$folderPath)

    $scriptComboBox.Items.Clear()
    Get-ChildItem $folderPath -Filter "*.ps1" | ForEach-Object {
        $scriptComboBox.Items.Add($_.Name)
    }
}

# Show the form
$form.ShowDialog()

# Clean up resources
$form.Dispose()