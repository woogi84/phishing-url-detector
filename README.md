## Phishing URL Detector

URL을 입력하면 피싱 여부를 분석하여 위험도 점수를 제공하는 보안 도구입니다.

## 주요 기능

- URL 특징 자동 추출 (길이, 특수문자, IP 직접 사용 등)
- 위험도 점수 산출 (0~100점)
- Streamlit 기반 웹 UI

## 기술 스택

- Python 3.10+
- Streamlit
- tldextract, requests

## 설치 및 실행

```bash
pip install -r requirements.txt
streamlit run app.py
```

## 프로젝트 구조

```
phishing-url-detector/
├── app.py              # Streamlit 메인 앱
├── detector/
│   ├── features.py     # URL 특징 추출
│   └── scorer.py       # 위험도 점수 계산
└── tests/
    └── test_features.py
```
