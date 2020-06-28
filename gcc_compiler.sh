#!/bin/bash
if [ -z "$1" ]; then # 실행 파일 인자값 포함 여부 조건식
	echo "usage: build.sh [TARGET_NAME]"
	echo ""
	echo "optional arguments:"
	echo "TARGET_NAME	컴파일 이름"
	echo "clean		오브젝트 제거"	
	exit 1
fi

if [ "$1" == "clean" ]; then # clean 작업 조건식
	echo "[*] rm -rf *.o"
	rm -rf *.o
	exit 1
fi

echo "[+] Build START"
build_count=0 # 컴파일 횟수
stop_count=0 # 종료

for file in *.c; do # 확장자 c로 끝나는 파일 처리
	filename=$(basename "$file")
	filename=${filename%.*}
	if [ $(basename "$file") -nt ${filename%.*}.o ]; then # 기존 오프젝트 빌드 날짜와 비교 조건식
		out_c=$(gcc -c $(basename "$file") 2>&1) # 컴파일 작업
		echo "[+] gcc -c $(basename "$file")" # 컴파일 성공
		if [ $? -ne 0 ]; then # 컴파일 상태 조건식
			echo "[+] Build stop !"
			echo [*] $file Errors # 컴파일 에러 출력
			exit 1
		elif grep "warning:" <<< "${out_c}" > /dev/null ; then # 컴파일 경고 조건식
			echo "[+] Build stop !"
			echo [*] $file Warnings # 컴파일 경고 출력
			rm -rf ${filename%.*}.o
			exit 1
		else
			build_count=$(($count+1)) # 컴파일하면 카운트 증가
    	fi
	fi
done

if [ $build_count -ne $stop_count ]; then # 컴파일 카운트 값에 따라 링크 진행
	target=$1
	out_o=$(gcc -o ${target%.*} *.o -lm 2>&1)
	echo "[+] gcc -o ${target%.*} *.o -lm" # 링크 성공
	if [ $? -ne 0 ]; then # 링크 상태 조건식
		echo "[+] Build stop !"
		echo [*] ${filename%.*}.o Errors # 링크 에러 출력
		rm -rf ${filename%.*}.o # 링크 파일 삭제
		exit 1
	elif grep "warning:" <<< "${out_o}" > /dev/null ; then # 링크 경로 조건식
		echo "[+] Build stop !"
		echo [*] ${filename%.*}.o Warnings # 링크 경고 출력
		rm -rf ${filename%.*}.o # 링크 파일 삭제
		exit 1
	elif grep "error:" <<< "${out_o}" > /dev/null ; then # 링크 경로 조건식
		echo "[+] Build stop !"
		echo [*] ${filename%.*}.o Warnings # 링크 경고 출력
		rm -rf ${filename%.*}.o # 링크 파일 삭제
		exit 1
	fi
fi

echo "[*] Build success !!!" # 빌드 완료