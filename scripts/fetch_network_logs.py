import kaggle
import pandas as pd
import os
import glob

# 다운로드할 Kaggle 데이터셋 정보
dataset_id = 'solarmainframe/ids-intrusion-csv'
# 사용할 CSV 파일
source_csv_filename = '02-14-2018.csv'
# 최종 저장될 파일 경로
output_csv_path = 'data/network_logs.csv'
# 사용할 행의 수
num_rows_to_keep = 1000

def fetch_logs_from_kaggle_and_generate_ips():
    """
    Kaggle API로 로그를 다운로드하고, IP 주소가 없는 문제를 해결하기 위해
    Flow ID와 Timestamp를 조합하여 가상의 IP 주소를 생성합니다.
    """
    download_path = 'data/kaggle_temp'
    
    print(f"'{dataset_id}' 데이터셋 다운로드 중...")
    try:
        kaggle.api.dataset_download_files(dataset_id, path=download_path, unzip=True, force=True)
        print("다운로드 및 압축 해제 완료.")
    except Exception as e:
        print(f"Kaggle API 오류: {e}")
        print("Kaggle API 설정이 올바른지 확인해주세요. (WSL의 경우 ~/.kaggle/kaggle.json)")
        return

    source_csv_path = os.path.join(download_path, source_csv_filename)

    if not os.path.exists(source_csv_path):
        print(f"오류: '{source_csv_path}' 파일을 찾을 수 없습니다.")
        cleanup_temp_files(download_path)
        return

    print(f"'{source_csv_filename}' 파일 처리 및 가상 IP 생성 중...")
    try:
        df = pd.read_csv(source_csv_path)
        df.columns = df.columns.str.strip()

        # IP 주소 대신 사용할 고유 식별자 생성
        # Flow ID와 Timestamp를 조합하여 src_ip, dst_ip 처럼 보이게 만듭니다.
        # Flow ID가 없어 다른 컬럼을 조합하여 고유성을 보장합니다.
        df['src_ip'] = df.index.astype(str) + '_src'
        df['dst_ip'] = df.index.astype(str) + '_dst'

        df_renamed = df[['dst_ip', 'src_ip', 'Dst Port', 'Protocol']].rename(columns={
            'Dst Port': 'dst_port',
        })
        
        protocol_map = {6.0: 'TCP', 17.0: 'UDP'}
        df_renamed['protocol'] = df_renamed['protocol'].map(protocol_map).fillna('Other')

        df_sample = df_renamed.head(num_rows_to_keep)
        df_sample.to_csv(output_csv_path, index=False)
        
        print(f"성공! '{output_csv_path}'에 {len(df_sample)}개의 가상 IP를 포함한 로그를 저장했습니다.")
        print("모든 데이터 교체 작업이 완료되었습니다.")

    except (KeyError, pd.errors.ParserError) as e:
        print(f"CSV 처리 중 오류 발생: {e}")
    finally:
        cleanup_temp_files(download_path)

def cleanup_temp_files(path):
    """
    다운로드한 임시 Kaggle 파일 및 디렉토리를 삭제합니다.
    """
    print(f"'{path}'의 임시 파일 정리 중...")
    try:
        # WSL 권한 문제를 피하기 위해 glob 대신 os.listdir 사용
        for filename in os.listdir(path):
            file_path = os.path.join(path, filename)
            try:
                if os.path.isfile(file_path):
                    os.remove(file_path)
            except OSError as e:
                print(f"임시 파일 삭제 실패: {file_path}, 오류: {e}")
        
        # 폴더 내 파일이 모두 삭제되었는지 확인 후 폴더 삭제 시도
        if not os.listdir(path):
            os.rmdir(path)
            print("임시 파일 정리 완료.")
    except OSError as e:
        print(f"임시 디렉토리 정리 실패: {e}")

if __name__ == "__main__":
    fetch_logs_from_kaggle_and_generate_ips()
