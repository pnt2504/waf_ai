import json
from typing import List, Dict, Any
import os

class FalseNegativeAnalyzer:
    def __init__(self, results_file: str):
        """
        Khởi tạo analyzer với đường dẫn tới file kết quả phân tích
        """
        self.results_file = results_file
        self.false_negatives = []

    def load_results(self) -> None:
        """
        Load kết quả từ file JSON
        """
        with open(self.results_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            # Hỗ trợ nhiều cấu trúc JSON đầu vào:
            if isinstance(data, dict):
                if 'results' in data and isinstance(data['results'], list):
                    self.results = data['results']
                elif 'requests' in data and isinstance(data['requests'], list):
                    self.results = data['requests']
                else:
                    # nếu dict nhưng không có key chuẩn, thử lấy list nằm trong values đầu tiên
                    possible = next((v for v in data.values() if isinstance(v, list)), None)
                    self.results = possible if possible is not None else []
            elif isinstance(data, list):
                self.results = data
            else:
                self.results = []

    def find_false_negatives(self) -> List[Dict[str, Any]]:
        """
        Tìm các request được dự đoán là Normal nhưng thực tế là Attack
        """
        self.false_negatives = [
            req for req in self.results 
            if isinstance(req, dict) and
               req.get('predicted') == 'Normal' and 
               req.get('original_label') == 'Attack'
        ]

        return self.false_negatives

    def extract_requests(self) -> List[Dict[str, Any]]:
        """
        Trích tất cả request từ self.results.
        Nếu record có key 'request' và là dict -> dùng luôn.
        Ngược lại xây dựng request từ các trường phổ biến (method/url/headers/body/payload/data/files).
        """
        extracted: List[Dict[str, Any]] = []
        for item in getattr(self, "results", []) or []:
            if isinstance(item, dict) and isinstance(item.get('request'), dict):
                extracted.append(item['request'])
                continue

            # Nếu item bản thân là request dict (có url hoặc method), dùng trực tiếp
            if isinstance(item, dict) and ('url' in item or 'method' in item or 'body' in item or 'payload' in item):
                # chọn các khóa phổ biến để giữ
                req: Dict[str, Any] = {}
                for k in ('method', 'url', 'headers', 'body', 'payload', 'data', 'files', 'cookies'):
                    if k in item:
                        req[k] = item[k]
                extracted.append(req)
                continue

            # fallback: không phải dict hoặc không có trường nào, bỏ qua
        return extracted

    def save_requests_to_file(self, output_path: str) -> None:
        """
        Ghi danh sách request đã trích xuất ra file JSON.
        """
        reqs = self.extract_requests()
        # đảm bảo thư mục tồn tại
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(reqs, f, ensure_ascii=False, indent=2)
        print(f"Saved {len(reqs)} requests to {output_path}")

    def analyze_patterns(self) -> Dict[str, int]:
        """
        Phân tích các pattern phổ biến trong false negatives
        """
        patterns = {
            'total': len(self.false_negatives),
            'methods': {},
            'url_patterns': {},
            'low_attack_weight': 0  # số request có attack_weight thấp
        }

        for req in self.false_negatives:
            # lấy request object nếu record chứa 'request'
            req_obj = req.get('request', req if isinstance(req, dict) else {})
            # Đếm theo method
            method = req_obj.get('method', req.get('method', 'UNKNOWN'))
            patterns['methods'][method] = patterns['methods'].get(method, 0) + 1

            # Phân tích URL patterns
            url = req_obj.get('url', req.get('url', ''))
            if 'wp-' in url:
                patterns['url_patterns']['wordpress'] = patterns['url_patterns'].get('wordpress', 0) + 1
            elif '.php' in url:
                patterns['url_patterns']['php'] = patterns['url_patterns'].get('php', 0) + 1

            # Đếm số request có attack_weight thấp
            # attack_weight có thể nằm trong features hoặc top-level hoặc trong request object
            aw = req.get('features', {}).get('attack_weight')
            if aw is None:
                aw = req.get('attack_weight', req_obj.get('attack_weight', 0))
            if aw < 100:
                patterns['low_attack_weight'] += 1

        return patterns

    def print_analysis(self) -> None:
        """
        In kết quả phân tích
        """
        print("\n=== False Negative Analysis ===")
        print(f"Total false negatives: {len(self.false_negatives)}")
        
        patterns = self.analyze_patterns()
        
        print("\nMethod distribution:")
        for method, count in patterns['methods'].items():
            print(f"  {method}: {count}")

        print("\nURL patterns:")
        for pattern, count in patterns['url_patterns'].items():
            print(f"  {pattern}: {count}")

        print(f"\nRequests with low attack weight: {patterns['low_attack_weight']}")

        # In chi tiết tất cả false negatives và các trường payload/ratio nếu có
        print("\nFalse negative requests (detailed):")
        for i, req in enumerate(self.false_negatives):
            req_obj = req.get('request', req if isinstance(req, dict) else {})
            feats = req.get('features', {})
            url = req_obj.get('url', req.get('url', 'N/A'))
            method = req_obj.get('method', req.get('method', 'N/A'))
            # ưu tiên attack_weight trong features -> top-level -> request object
            attack_weight = feats.get('attack_weight', req.get('attack_weight', req_obj.get('attack_weight', 'N/A')))
            payload_len = feats.get('payload_len', req.get('payload_len', req_obj.get('payload_len', 'N/A')))
            alpha_ratio = feats.get('alpha_ratio', req.get('alpha_ratio', req_obj.get('alpha_ratio', 'N/A')))
            nonalpha_ratio = feats.get('nonalpha_ratio', req.get('nonalpha_ratio', req_obj.get('nonalpha_ratio', 'N/A')))

            print(f"\n{i+1}. URL: {url}")
            print(f"   Method: {method}")
            print(f"   Attack Weight: {attack_weight}")
            print(f"   payload_len: {payload_len}, alpha_ratio: {alpha_ratio}, nonalpha_ratio: {nonalpha_ratio}")

    def save_summary(self, out_path: str) -> None:
        """
        Ghi file JSON chứa summary của false negatives với các trường:
        url, method, attack_weight, payload_len, alpha_ratio, nonalpha_ratio, predicted, original_label
        """
        import os
        summaries: List[Dict[str, Any]] = []
        for req in self.false_negatives:
            req_obj = req.get('request', req if isinstance(req, dict) else {})
            feats = req.get('features', {})

            url = req_obj.get('url', req.get('url', 'N/A'))
            method = req_obj.get('method', req.get('method', 'N/A'))

            attack_weight = feats.get('attack_weight', req.get('attack_weight', req_obj.get('attack_weight', 0)))
            payload_len = feats.get('payload_len', req.get('payload_len', len(req_obj.get('body', req_obj.get('payload', '')))))
            alpha_ratio = feats.get('alpha_ratio', req.get('alpha_ratio', req_obj.get('alpha_ratio', None)))
            nonalpha_ratio = feats.get('nonalpha_ratio', req.get('nonalpha_ratio', req_obj.get('nonalpha_ratio', None)))

            summaries.append({
                "url": url,
                "method": method,
                "attack_weight": attack_weight,
                "payload_len": payload_len,
                "alpha_ratio": alpha_ratio,
                "nonalpha_ratio": nonalpha_ratio,
                "predicted": req.get('predicted'),
                "original_label": req.get('original_label'),
            })

        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(summaries, f, ensure_ascii=False, indent=2)
        print(f"Saved false negative summary to {out_path} ({len(summaries)} items)")

def main():
    analyzer = FalseNegativeAnalyzer(r'd:\Tai lieu 20251\Project 3\Code xử lí\csic_analysis_results.json')
    analyzer.load_results()
    analyzer.find_false_negatives()
    # Xuất file JSON mới với summary các false negatives
    analyzer.save_summary(r'd:\Tai lieu 20251\Project 3\Code xử lí\false_negative_summary.json')
    analyzer.print_analysis()

if __name__ == "__main__":
    main()
