import json
from typing import List, Dict, Any

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
            self.results = data['results']

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
            # Đếm theo method
            method = req.get('method', 'UNKNOWN')
            patterns['methods'][method] = patterns['methods'].get(method, 0) + 1

            # Phân tích URL patterns
            url = req.get('url', '')
            if 'wp-' in url:
                patterns['url_patterns']['wordpress'] = patterns['url_patterns'].get('wordpress', 0) + 1
            elif '.php' in url:
                patterns['url_patterns']['php'] = patterns['url_patterns'].get('php', 0) + 1

            # Đếm số request có attack_weight thấp
            if req.get('attack_weight', 0) < 100:
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

        print("\nSample false negative requests:")
        for i, req in enumerate(self.false_negatives[:5]):  # In 5 ví dụ đầu tiên
            print(f"\n{i+1}. URL: {req.get('url', 'N/A')}")
            print(f"   Method: {req.get('method', 'N/A')}")
            print(f"   Attack Weight: {req.get('attack_weight', 'N/A')}")

def main():
    analyzer = FalseNegativeAnalyzer(r'd:\Tai lieu 20251\Project 3\Code xử lí\csic_analysis_results.json')
    analyzer.load_results()
    analyzer.find_false_negatives()
    analyzer.print_analysis()

if __name__ == "__main__":
    main()
