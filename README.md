### 说明
-1、在 main_pipeline_process_logs.py 中替换以下内容：
pipeline_jobs = [
        {"project": "audiohal", "source_dir": r"/home/amlogic/FAE/AutoLog/lingzhi.bi/extract_module_errlog_and_identitication/audio_hal_01201212/audio_hal"}
]
注意：需要在提取的代码目录前添加创建一个wapper目录，用于存放提取的代码
-2、自动生成打印代码的提取,放在audio_hal_01201212目录下，

-3、然后 rag_store_filter_log https://github.com/bilingzhi05/rag_store_filter_log 项目才能过滤打印的内容
