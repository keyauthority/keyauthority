import { Row, Col, Card } from "react-bootstrap";

/*

example cards:
[
  {
    key: "Total Certificates",
    value: 100,
    valueClass: "text-primary"
  },
  {
    key: "Expiring Soon",
    value: 20,
    valueClass: "text-warning"
  },
  {
    key: "Expired",
    value: 10,
    valueClass: "text-danger"
  }
]

filters, setFilters: state and setter for filters object (for parent component to react to filter changes)

*/

export default function Dashboard({ cards, colsPerRow = 4 }) {
  const safeColsPerRow =
    Number.isInteger(colsPerRow) && colsPerRow > 0 ? colsPerRow : 4;

  const baseSpan = 12 / safeColsPerRow;
  const supportsFill = Number.isInteger(baseSpan); // exact fill only when colsPerRow divides 12
  const remainder = supportsFill ? cards.length % safeColsPerRow : 0;

  return (
    <Row className="g-3 mb-3">
      {cards.map((card, index) => {
        const isLast = index === cards.length - 1;

        const md =
          supportsFill && isLast && remainder !== 0
            ? 12 - baseSpan * (remainder - 1) // last item fills remaining space
            : supportsFill
              ? baseSpan
              : undefined;
        return (
          <Col xs={12} md={md} key={card.key}>
            <Card className="h-100">
              <Card.Body>
                <div className={`h4 mb-0 ${card.valueClass || ""}`}>
                  {card.value}
                </div>
                <div className="text-muted small">{card.key}</div>
              </Card.Body>
            </Card>
          </Col>
        );
      })}
    </Row>
  );
}
