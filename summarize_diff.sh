
file_path=""
while IFS= read -r line
do
    if [[ $line == diff* ]]
    then
        file_path=$(echo $line | awk "{print \$3}")
        echo "File Changed: $file_path"
    elif [[ $line == index* || $line == ---* || $line == +++* ]]
    then
        continue
    else
        echo "$line"
    fi
done < ~/full_outputs/git_diff_main_devin__1714789982.1024153.txt

